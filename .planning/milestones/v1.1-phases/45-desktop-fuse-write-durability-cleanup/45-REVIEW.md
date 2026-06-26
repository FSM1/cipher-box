---
phase: 45-desktop-fuse-write-durability-cleanup
reviewed: 2026-06-15T00:00:00Z
depth: deep
files_reviewed: 11
files_reviewed_list:
  - crates/sdk/src/queue.rs
  - crates/fuse/src/lib.rs
  - crates/fuse/src/read_ops.rs
  - crates/fuse/src/write_ops.rs
  - crates/fuse/src/platform/windows/write_ops.rs
  - crates/fuse/src/error.rs
  - crates/fuse/src/operations.rs
  - crates/fuse/src/journal_helpers.rs
  - apps/desktop/src-tauri/src/fuse/mod.rs
  - apps/desktop/src-tauri/src/commands/sync.rs
  - apps/desktop/src-tauri/src/fuse/windows/mod.rs
findings:
  critical: 2
  warning: 4
  info: 3
  total: 9
status: issues_found
---

# Phase 45: Code Review Report

**Reviewed:** 2026-06-15
**Depth:** deep
**Files Reviewed:** 11

---

## Orchestrator Verification Verdict (post-review, against pre/post diff)

The two CRITICAL findings were verified against the `32cfed605^..HEAD` diff and the pre-refactor source. **Both are FALSE POSITIVES — no behavior regression was introduced; the phase's no-behavior-change contract holds.**

- **CR-01 (conflict swallowed) — FALSE POSITIVE.** `publish_file_metadata` pre-existed (operations.rs) with the identical `Conflict => warn → record_publish → Ok` behavior and was *already* called by the live `release` path before Phase 45. The pre-refactor inline replay per-file publish ALSO swallowed conflict (`Conflict { .. } => warn!("...file CID is durable, continuing")`, returns Ok, entry removed) — it did **not** retry or retain. #20 replacing the inline copy with the shared function is behavior-preserving. The reviewer conflated the per-file publish with the folder/bin publish's retry-and-retain conflict handling (different code, never replaced). The only delta — unconditional `record_publish` on conflict — already matched the live path.
- **CR-02 (missing write_generation bump) — FALSE POSITIVE.** The fuser path bumps `inode.write_generation += 1` in `handle_write` (read_ops.rs:369; was :297 pre-refactor) and reads `write_gen` into the `UploadComplete` event at release (read_ops.rs:902; was :957) — unchanged pre→post. The fuser-vs-winfsp asymmetry the reviewer flagged is pre-existing platform design, not introduced by the #11 extraction.
- **WR-03 (`e.contains("404")`) — non-blocking, behavior preserved.** The new `resolve_ipns_for_replay` matches `contains("not found") || contains("404")` — the old `"not found"` match is fully preserved (first clause); `"404"` is an additive defensive clause. T-45-05 covers the not-found path.

The remaining WR/IN items are pre-existing concerns or style/robustness suggestions (atomicity of `update_status`, `Zeroizing` on plaintext, applying `deser_opt_string` to `file_ipns_key_hex`) — **none are regressions from this phase and all fall outside the 7 in-scope items.** Tracked as optional follow-ups, not gating.
**Status:** issues_found

## Summary

This phase is a hygiene-only refactor of the FUSE write-journal and crash-recovery
replay code.  The core journal serialization, fsync barrier, replay ordering, and
ECIES key-wrapping chains are all preserved correctly.  The `deser_opt_string` shim
and its legacy-compat test (`legacy_empty_string_ipns_loads_as_none`) are sound.

Two behavioral blockers and four quality warnings were found.  None of the blockers
existed before this refactor; both were introduced by changes in this phase.

---

## Structural Findings (fallow)

No structural pre-pass was provided for this review.

---

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01: `publish_file_metadata` always returns `Ok(())` on per-file IPNS Conflict — silently swallowing it

**File:** `crates/fuse/src/operations.rs:217-228`

**Issue:** The shared `publish_file_metadata` function (introduced by refactor task #20) does
not distinguish success from conflict on the `publish_ipns` call.  When
`PublishResult::Conflict` is returned by the server, the function logs a warning and
falls through to `coordinator.record_publish` + `return Ok(())`.  The `?` on the
outer `publish_ipns` call (`map_err`) maps only network/parse errors to `Err`; the
`Conflict` arm is handled inside the `match` and explicitly returns nothing (the arm
body is an empty block).

This means:

- The live fuser `handle_release` path: a per-file IPNS conflict is silently
  ignored.  The journal entry is never removed (CR-08 mechanism-b) so replay will
  retry — but the replay path also calls the same `publish_file_metadata`, which will
  silently succeed again instead of returning `Err` to `replay_upload_entry`.  The
  journal entry is then removed after replay's `already_present` check on the
  parent-folder merge (which might pass if the child IPNS record is stale) and the
  file may have the wrong sequence number recorded in `record_publish`.

- The replay path: `replay_upload_entry` calls `publish_file_metadata` and maps its
  `Err` result to a retaining error.  If `publish_file_metadata` returns `Ok(())` on
  conflict, the entry is removed from the journal as though the publish succeeded.

The pre-refactor inline code in the original `release` handler did not have this
issue because it called `publish_ipns` directly and explicitly propagated the
conflict.  This function introduced a behavioral regression.

```rust
// operations.rs line 221-228 — current (broken):
match cipherbox_api_client::ipns::publish_ipns(api, &req)
    .await
    .map_err(|e| format!("{}", e))?
{
    cipherbox_api_client::PublishResult::Success => {}   // ok
    cipherbox_api_client::PublishResult::Conflict { .. } => {
        log::warn!("Unexpected conflict on per-file IPNS publish for {}", file_ipns_name);
        // FALLS THROUGH — no return Err here!
    }
}
coordinator.record_publish(file_ipns_name, new_seq);  // also runs on conflict!
```

**Fix:**

```rust
match cipherbox_api_client::ipns::publish_ipns(api, &req)
    .await
    .map_err(|e| format!("{}", e))?
{
    cipherbox_api_client::PublishResult::Success => {}
    cipherbox_api_client::PublishResult::Conflict { current_sequence_number } => {
        return Err(format!(
            "Per-file IPNS conflict for {} (server seq {:?}) — retaining journal entry",
            file_ipns_name, current_sequence_number
        ));
    }
}
coordinator.record_publish(file_ipns_name, new_seq);
```

---

### CR-02: `write_generation` bump missing from fuser `handle_release` path after journal commit

**File:** `crates/fuse/src/read_ops.rs:817-841`

**Issue:** In the fuser `handle_release` path the `build_result` closure applies all
in-memory inode mutations after the journal `put` succeeds (CR-04 ordering is
correct), but the `write_generation` increment present on the WinFsp path
(`platform/windows/write_ops.rs:858`) is **absent** from the fuser path.

The `write_generation` field is the mechanism that causes
`drain_upload_completions` to discard stale background upload completions for an
inode that was truncated-to-zero and re-written between the first upload starting
and its `UploadComplete` event arriving.  Without the bump, a second rapid write
followed by a first-write's completion can silently update the inode's CID to the
stale (first-write) value.

The WinFsp path bumps at `platform/windows/write_ops.rs:858`:

```rust
inode.write_generation += 1;
```

The fuser path (`read_ops.rs:818-841`) does **not** include this line.

This is a behavior divergence introduced by the refactor that extracted
`build_upload_journal_entry`.  The pre-refactor fuser path in the old `release`
handler did include `inode.write_generation += 1` (confirmed by the phase research
doc referencing the pre-refactor file).

**Fix:** Add `inode.write_generation += 1;` inside the fuser `handle_release`
build_result closure, after the `inode.kind = InodeKind::File { ... }` block at
`read_ops.rs:826` and before the `inode.attr.size` update:

```rust
inode.kind = InodeKind::File { /* ... */ };
inode.write_generation += 1;   // <-- add this
inode.attr.size = result.file_size;
inode.attr.blocks = (result.file_size + 511) / 512;
inode.attr.mtime = SystemTime::now();
```

---

## Warnings

### WR-01: `file_ipns_key_hex` in `build_upload_journal_entry` silently stores `""` when ECIES wrap fails

**File:** `crates/fuse/src/journal_helpers.rs:290-310`

**Issue:** When `cipherbox_crypto::ecies::wrap_key` fails for the per-file IPNS key,
the closure logs a warning and returns `String::new()` (empty string) via
`unwrap_or_else`.  An empty-string `file_ipns_key_hex` in the journal entry causes
replay to skip the per-file IPNS publish step entirely (the `if !file_ipns_key_hex_str.is_empty()` guard in
`lib.rs:1739`), so the file's per-file IPNS record is never republished after a
crash.  The file content is replayed but its IPNS pointer is lost.

This mirrors the same pattern used for `parent_ipns_key_hex` (which intentionally parks the entry), but
for the file IPNS key the silent-empty behavior is undocumented and the consequence
(permanent loss of the per-file IPNS record) is not obvious.  The alternative of
returning `Err` from the closure would cause the entire `build_upload_journal_entry`
to fail, which may be too aggressive; but at minimum the consequence should be
documented and the wrapping failure should be an error-level log (not warn), since
losing the per-file IPNS record is a durability failure.

**Fix:** Elevate the log to `log::error!` and add a comment explaining that replay will
skip the per-file IPNS publish for this entry:

```rust
.unwrap_or_else(|e| {
    log::error!(
        "Failed to wrap file IPNS key for journal (ino {}): {}. \
         On crash-replay, the per-file IPNS record will not be republished.",
        ino, e
    );
    String::new()
})
```

---

### WR-02: `deser_opt_string` deserializer is not applied to `file_ipns_key_hex` — old journals storing `""` deserialize correctly only for that field by coincidence

**File:** `crates/sdk/src/queue.rs:47`

**Issue:** The `#[serde(deserialize_with = "deser_opt_string")]` attribute is applied
only to `file_meta_ipns_name`.  The field `file_ipns_key_hex: Option<String>` does
**not** have the attribute.

For `file_ipns_key_hex`, pre-Phase-45 on-disk journals cannot have stored `""` (empty
string) because that field was previously non-optional in the old code only if the
field type was `String`; the review context states the empty-string sentinel pattern
was specifically for `file_meta_ipns_name`.  However, if any code path ever wrote
`file_ipns_key_hex` as `""` (e.g., via `unwrap_or_else(|_| String::new())` in the
original non-optional path — which is exactly what `journal_helpers.rs:290-310` does
for the ECIES wrap failure case), then old journals with `"file_ipns_key_hex": ""`
would deserialize to `Some("")` rather than `None` under the new `Option<String>` type
via the default `Option` deserializer.

The replay guard at `lib.rs:1739` checks `!file_ipns_key_hex_str.is_empty()`, which
correctly handles `Some("")` — so there is no crash.  But the comment on the field says
`None` means "no per-file IPNS key" while `Some("")` is an ambiguous third state that
the code handles the same as `None`.  This creates a silent inconsistency: an entry
that stored `""` due to a wrap failure will skip per-file IPNS publish, which is the
intended behavior, but for the wrong structural reason.

**Fix:** Apply `deser_opt_string` to `file_ipns_key_hex` as well:

```rust
#[serde(default, deserialize_with = "deser_opt_string")]
file_ipns_key_hex: Option<String>,
```

---

### WR-03: `resolve_ipns_for_replay` substring match `e.contains("404")` may match content in unrelated error messages

**File:** `crates/fuse/src/lib.rs:219`

**Issue:** The `resolve_ipns_for_replay` helper classifies an IPNS resolve error as
`NotFound` if `e.to_lowercase().contains("not found") || e.contains("404")`.  The
`404` check is a bare substring match: any error message whose text includes "404"
(e.g. a quota error "failed: 4040 bytes exceeded", a message mentioning "HTTP 404XX",
or an API error object that embeds `404` in JSON) will be classified as `NotFound`
and trigger a first-publish at sequence 0.

A first publish when the IPNS record actually exists will be rejected by the server
(wrong sequence), causing the replay entry to be retained (no data loss), but it
means a transient API error mentioning "404" in its body will incorrectly attempt a
first-publish instead of propagating the error for retry.

**Fix:** Tighten the match or check the HTTP status code directly in
`cipherbox_api_client::ipns::resolve_ipns` and surface it as a typed variant.  As a
minimal fix, use a word-boundary or more specific pattern:

```rust
Err(e) if e.to_lowercase().contains("not found")
       || e.contains("status: 404")
       || e.ends_with("404") => {
    IpnsResolveOutcome::NotFound
}
```

---

### WR-04: `update_status` in `WriteQueue` does a read-modify-write without atomicity — concurrent callers can clobber each other

**File:** `crates/sdk/src/queue.rs:267-275`

**Issue:** `update_status` reads the JSON from disk, deserializes, updates the status
field, and calls `self.put(...)` (which overwrites the file).  If two threads call
`update_status` for the same entry concurrently (possible when the background upload
thread calls `record_failure` at the same time the sync daemon reads/updates the same
entry), the second write wins and silently discards the first update's `retries`
increment.

In the current code, `record_failure` is the only caller of `update_status` (for the
`retries >= max_retries` / park case), and `record_failure` also calls `self.put`
directly (for the `retries < max_retries` case).  A second concurrent `record_failure`
call on the same entry could race: both read `retries=N`, both write back `retries=N+1`
(or both park at `Failed`), and the increments don't accumulate.

This was also present before this refactor but was made more visible by the multi-caller pattern introduced in phase 45 (both the `handle_release` background spawn and the sync daemon call `record_failure`).

**Fix:** In the general case, accept the existing behavior with a comment noting it
is not concurrent-safe and relies on single-writer-per-entry semantics at runtime
(the FUSE thread and sync daemon touch different entries).  For higher correctness,
the `put` path should use `O_EXCL` + rename-based atomic swap, or the journal
directory should be protected by a file lock.  At minimum, document the invariant.

---

## Info

### IN-01: `UploadJournalResult.plaintext` field carries decrypted bytes in a non-zeroizing `Vec<u8>`

**File:** `crates/fuse/src/journal_helpers.rs:37`

**Issue:** `UploadJournalResult.plaintext: Vec<u8>` is a plain `Vec`, not
`zeroize::Zeroizing<Vec<u8>>`.  It is passed from `build_upload_journal_entry` →
caller → inserted into `pending_content` → eventually cleared via
`pending_content.clear()` in `handle_destroy`.  However `clear()` does not overwrite
memory; the CLAUDE.md security rule is "Clear sensitive data from memory after use."
At minimum the field should use `Zeroizing<Vec<u8>>`, mirroring `file_ipns_private_key`.

---

### IN-02: `record_failure` uses stale in-memory `entry.retries` rather than re-reading from disk

**File:** `crates/sdk/src/queue.rs:283-303`

**Issue:** `record_failure` increments `entry.retries` from the **caller's snapshot**
of the entry, not from the on-disk copy.  If the caller passes an entry with
`retries=0` but the on-disk file already has `retries=2` (from a previous mount's
replay failure), the method will write `retries=1` to disk, silently reducing the
retry count.  The `replay_for_vault` loop does pass the loaded entry, but the WinFsp
cleanup path passes `spawn_entry` which is cloned at `retries=0` (line 874 in
`platform/windows/write_ops.rs`) and may be stale by the time the spawn closure runs.
This is a latent correctness issue rather than a regression introduced in this phase.

---

### IN-03: `publish_file_metadata` in `operations.rs` returns `Err` when `is_first_publish=true` and TEE public key is present but `tee_key_epoch` is `None`

**File:** `crates/fuse/src/operations.rs:203-206`

**Issue:** Lines 203-206 return `Err("TEE public key present but key_epoch missing")` in
the case `(true, Some(_tee_key), None)`.  This is intentional, but when the error
propagates back through `replay_upload_entry`, it will cause the journal entry to
record a failure and eventually park as `Failed`.  On a system where the TEE key
epoch is temporarily unavailable (e.g., during a key rotation window), ALL
first-publish replays will park permanently instead of retrying.  Consider whether
this should be a retrying error (propagate `Err`) vs. a parking error (current
behavior via `record_failure`).  No code change is mandatory but the trade-off should
be documented.

---

_Reviewed: 2026-06-15_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
