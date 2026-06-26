# Phase 46: Desktop FUSE data-loss bugs + replay hardening - Research

**Researched:** 2026-06-15
**Domain:** Rust desktop FUSE durability / IPNS replay correctness (crates/fuse, crates/sdk, apps/desktop/src-tauri)
**Confidence:** HIGH (all findings grounded in current source with file:line anchors)

## Summary

This is a Rust-only correctness/durability phase. Five of the six requirements touch crash-recovery
semantics; the sixth is test infrastructure that unblocks unit testing the FUSE handlers. The most
important research finding is that **two of the six "bugs" in the original todos are already largely
fixed in the current tree** by Phase 43/45 work — the todos predate those landings:

- **Requirement 1 (mkdir orphan)** is already handled on BOTH platforms via `FsEvent::MkdirConflict`
  + the durable journal entry (D-11a/D-11b). The "warn-only, never retries" TODO referenced in the
  todo no longer exists at `write_ops.rs:659` or `windows/write_ops.rs:194`. The residual work is a
  verification/test gap, not a missing retry.
- **Requirement 2 (release data loss)** is already closed by the D-04 journal-before-ack barrier. The
  ciphertext is captured into the fsynced `JournalEntry.ciphertext_b64` BEFORE `handle.cleanup()`
  deletes the temp file, so temp-file deletion does NOT orphan recovery. The residual window is small
  and specific (see Requirement 2).

Requirements 4 and 5 are genuine, still-present pre-existing bugs (CodeRabbit on PR #491). Requirement
3 (Linux stale-mount) and Requirement 6 (test harness) are real, unimplemented work.

**Primary recommendation:** Treat requirements 1 and 2 as "verify current behavior + add the missing
characterization test" rather than rebuilds. Implement 3, 4, 5 as the minimal targeted changes below.
Implement 6 first (it unblocks unit tests that prove 1, 2, 4, 5).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
| ---------- | ------------ | -------------- | --------- |
| mkdir conflict retry (req 1) | FUSE callback + debounced publisher (crates/fuse) | Durable journal (crates/sdk WriteQueue) | Conflict resolution is in-FS-thread state (`mutated_folders`); journal is the crash-recovery backstop |
| release durability (req 2) | Durable journal (crates/sdk) | FUSE release callback (crates/fuse) | Durability MUST come from the out-of-callback journal — release cannot block on network |
| Linux stale-mount recovery (req 3) | Desktop mount glue (apps/desktop/src-tauri/src/fuse/mod.rs) | Linux platform unmount (crates/fuse/platform/linux.rs) | Mount lifecycle is Tauri-side; unmount tooling already lives in the fuse crate |
| replay classification (req 4, 5) | Replay orchestration (crates/fuse/src/lib.rs) | PublishCoordinator (crates/fuse/src/lib.rs) | Replay decides remove-vs-retain; coordinator owns resolve+cache |
| handler test harness (req 6) | crates/fuse test support + vendored fuser | — | The ReplySender export gate lives in the vendored crate; test sender lives in cipherbox-fuse |

## Requirement 1: mkdir must durably retry parent publish on conflict

### Current Behavior (file:line)

The todo describes a "warn-only, never enqueues retry" arm. **That code no longer exists.** The current
tree already implements durable retry on BOTH platforms:

- macOS/Linux: `crates/fuse/src/write_ops.rs:670-679` — on `PublishResult::Conflict`, the spawned
  thread logs the conflict and sends `crate::FsEvent::MkdirConflict { parent_ino }` via `upload_tx`
  (D-11a). The journal entry is NOT removed (D-11b, comment at `write_ops.rs:672-673`).
- Windows/WinFsp: `crates/fuse/src/platform/windows/write_ops.rs:261-270` — identical pattern, sends
  `FsEvent::MkdirConflict { parent_ino: parent_ino_for_conflict }` at line 269, retains journal entry.
- The event is consumed in `crates/fuse/src/lib.rs:927-933` (`FsEvent::MkdirConflict`): it re-inserts
  `parent_ino` into `mutated_folders` and calls `self.queue_publish(parent_ino, false)` — exactly the
  "actually enqueue the parent for retry" the todo asked for.
- Crash-before-thread-runs is covered separately: the journal entry is fsynced BEFORE `reply.entry()`
  (`write_ops.rs:555-559`, `windows/write_ops.rs:162-167`), and on next mount `replay_for_vault` →
  `replay_mkdir_entry` republishes the parent (D-11b).

So the original "child orphaned, key only in unpublished parent metadata, irrecoverable after restart"
data-loss scenario is already closed by the journal. The parent inode already contains the new child
in its `children` vec (`write_ops.rs:520-526`) before the journal is built, so the re-armed debounced
publish carries the child pointer.

### Minimal Change

The retry mechanism exists. The residual gaps to verify/close:

1. **Confirm `MkdirConflict` is actually drained.** `drain_upload_completions` (which processes
   `upload_rx`) is called from `readdir`/`release` paths. If a vault sits idle with no FUSE traffic
   after a mkdir conflict, the event may sit in the channel unprocessed until the next callback. This
   is the same delivery model as `UploadComplete`, so it is consistent with existing semantics — but
   the plan should confirm no regression and that the debounced safety-valve (10s) still fires.
2. **The spawned-thread conflict path does NOT merge** (unlike `spawn_metadata_publish` at
   `lib.rs:440-527` which fetch-merges remote children). It relies on the re-armed debounced publisher
   to re-resolve sequence and republish. Verify the debounced publisher does a fetch-and-merge so a
   concurrent remote edit to the parent is not clobbered. If it blind-overwrites, that is a latent
   bug to fix here.

Net: this requirement is primarily a **characterization-test + verification** task, not a rewrite. Do
NOT reintroduce a warn-only arm.

### Risk

LOW for the retry mechanism (already present). MEDIUM if step-2 reveals the debounced parent
republish does not merge — that would be a separate clobber bug.

### Test

- Unit (needs req-6 harness): `handle_mkdir` happy-path — assert journal entry is `put` before reply,
  and inode/children mutated. Capture reply wire bytes → `error == 0`.
- Characterization: an `FsEvent::MkdirConflict { parent_ino }` fed through `drain_upload_completions`
  results in `parent_ino ∈ mutated_folders` and a `publish_queue` entry (pure in-memory, no network).
- E2E/manual: induce a real parent-publish conflict (concurrent device) and confirm the child folder
  resolves remotely after the debounce window.

## Requirement 2: release()/flush must not lose data before durable commit

### Current Behavior (file:line)

`handle_release` in `crates/fuse/src/read_ops.rs:773-975`. The relevant durability ordering:

1. `fs.build_upload_journal_entry(ino, &handle, is_new_file)` (`read_ops.rs:808`) reads the plaintext
   from the temp file (`journal_helpers.rs:134 handle.read_all()`), encrypts it, and base64-encodes the
   **ciphertext into `JournalOp::UploadFile.ciphertext_b64`** (`journal_helpers.rs:286, 311`).
2. `fs.journal.put(&result.entry)` (`read_ops.rs:815`) fsyncs the entry to disk (`queue.rs:171-200`,
   `sync_all()` = F_FULLFSYNC on macOS) — comment "D-04: fsync journal entry to disk BEFORE acking the
   OS" (`read_ops.rs:814`).
3. Only AFTER the journal fsync: in-memory inode mutation (`read_ops.rs:818-841`), `pending_content`
   insert (`843`), `queue_publish` (`845`).
4. `handle.cleanup()` (`read_ops.rs:882`) zeroizes + deletes the temp file — comment "D-05: zeroize and
   delete plaintext temp file BEFORE acking OS".
5. `reply.ok()` (`read_ops.rs:884`) — comment "D-04: ack OS only after local journal fsync is confirmed".
6. Detached thread (`read_ops.rs:888-956`) uploads ciphertext; on failure calls
   `spawn_journal.record_failure` (`942`) — NOT a silent `log::error!` swallow. The entry stays in the
   journal until the parent pointer publish is confirmed on a later mount (comment CR-08 at `926-933`).

**Key finding (answers the todo's central question):** After `release` acks + journals, the
**ciphertext is fully recoverable on crash** because it lives in the fsynced journal entry, NOT only in
the deleted temp file. The temp-file deletion at `read_ops.rs:882` does NOT orphan the journal entry —
the ciphertext was copied into the entry at step 1. On next mount, `replay_upload_entry`
(`lib.rs:1828`) re-uploads `ciphertext_b64` (`lib.rs:1869-1874`) and re-publishes. The 2026-06-11 todo
predates the D-04 barrier and describes the pre-Phase-43 state.

`handle_flush` is a no-op (`read_ops.rs:978-980`, `reply.ok()`). This is correct: durability is on
`release`, and FUSE may call `flush` multiple times per open without a final close. The Windows
equivalent (`windows/write_ops.rs:837-879`) mirrors the same journal-before-spawn ordering with an
added `write_generation` bump (`872`).

### Residual data-loss window (post-Phase-43/45)

The remaining gaps are narrow:

1. **`UploadComplete` not journaled-after.** After the background upload succeeds, the content CID is
   delivered via `FsEvent::UploadComplete` and applied in-memory (`lib.rs:896-925`); the journal entry
   is intentionally retained (CR-08) until the parent pointer publish confirms on next mount. This is
   correct but means a successful upload whose parent-publish never confirms re-runs on next mount
   (idempotent — same plaintext → same CID). No data loss; possible duplicate work. Verify idempotency
   holds for the versioning path (`apply_versioning` could double-append a version on replay).
2. **`flush` returning OK without forcing a not-yet-released dirty handle to durability.** If an
   application calls `fsync`/`flush` and expects durability but never calls `release` (rare, but POSIX
   permits long-lived open handles), the dirty bytes are only in the temp file, not yet journaled. The
   journal entry is built on `release`, not `flush`. This is the one true residual gap: a crash after
   `flush` but before `release` loses the un-released write. Closing it would mean journaling on
   `flush` too — but that risks regressing the single-thread constraint and double-journaling.
   **Recommendation:** document this as an accepted limitation (matches every temp-file-backed FUSE
   design) OR, if in scope, make `flush` journal the current temp-file contents idempotently keyed by
   `(ino, write_generation)` so a duplicate `release` journal entry is de-duplicated. Lowest-risk is to
   leave `flush` a no-op and document the window; do not regress D-04.

### Minimal Change

Likely **no functional change** to release ordering — it already satisfies the durability contract.
Scope this requirement to: (a) add the missing characterization tests proving journal-before-cleanup
ordering, (b) verify replay idempotency for the versioning path, (c) decide and document the
flush-window policy. If the flush window must be closed, do it idempotently and behind a test.

### Risk

HIGH if anyone "fixes" release by blocking on the network (violates single-thread constraint) or by
removing the journal-before-cleanup ordering (regresses D-04). The safe posture is verification +
tests, not restructuring.

### Test

- Unit (req-6 harness + a real temp WriteQueue dir): `handle_release` on a dirty new file → assert a
  journal entry exists on disk AND `handle.cleanup()` ran (temp file gone) AND reply `error == 0`,
  with no live network (the detached upload thread will fail to `http://127.0.0.1:1` and call
  `record_failure`, which must NOT remove the entry).
- Characterization: build entry, crash-simulate by NOT running the spawn, reload via
  `load_all_for_vault`, assert `ciphertext_b64` decodes to the original ciphertext.
- `handle_flush` returns OK (trivial unit test).

## Requirement 3: Linux startup must auto-recover stale/disconnected FUSE mount

### Current Behavior (file:line)

`mount_filesystem` in `apps/desktop/src-tauri/src/fuse/mod.rs:74-325`, gated `#[cfg(feature = "fuse")]`
(covers BOTH macOS and Linux; macOS uses FUSE-T). Platform is distinguished by `#[cfg(target_os = ...)]`
— e.g. mount options at `mod.rs:295` (linux) vs `297` (macos); unmount dispatch at `mod.rs:327`
(macos) / `332` (linux).

The buggy branch is `mod.rs:89-110` (the todo cited `:65-86`; the file has shifted):

```rust
if mount_path.is_symlink() { return Err(...) }            // :89-91
if !mount_path.exists() {                                  // :93
    std::fs::create_dir_all(&mount_path)                   // :94 → EEXIST on disconnected mount
        .map_err(|e| format!("Failed to create mount point: {}", e))?;
    // set 0o700 ...
} else {
    // read_dir + remove stale entries, log "Cleaned stale mount point"  // :101-109
}
```

Root cause exactly as the todo states: a disconnected FUSE mount makes `stat()` return ENOTCONN, so
`mount_path.exists()` returns `false` → takes the `create_dir_all` branch → the dirent still exists →
EEXIST (os error 17) → user-facing "Failed to create mount point". This is Linux-only: macOS FUSE-T
leaves the path as a normal dir; Windows/WinFsp uses a different mount path entirely.

A reusable unmount helper already exists: `crates/fuse/src/platform/linux.rs:8` `unmount_filesystem()`
tries `fusermount3 -u`, then `fusermount -u`, then `umount`. It does NOT currently try lazy `-z`.

### Minimal Change

Add a Linux-only stale-mount detection + unmount step before the `create_dir_all` decision. Cleanest
minimal approach (Linux only, `#[cfg(target_os = "linux")]`), inserted just after the `is_symlink`
guard at `mod.rs:91`:

1. Detect a stale mount authoritatively: read `/proc/self/mountinfo` and check whether `mount_path`
   appears as a mountpoint (do NOT rely on `exists()` — it lies for ENOTCONN). Alternatively, treat an
   `Err(ENOTCONN)` from a direct `std::fs::symlink_metadata`/`statfs` probe as "stale present".
2. If stale: run `fusermount3 -u <path>`; on failure run `fusermount3 -z -u <path>` (lazy). Then fall
   through to the normal `exists()` / `create_dir_all` / clean-stale logic, which now succeeds.
3. Belt-and-suspenders: also map `create_dir_all`'s `ErrorKind::AlreadyExists` (EEXIST) to "attempt
   unmount, then retry once" rather than erroring out immediately.

Implementation notes:

- Add a `pub fn recover_stale_mount(mount_path: &Path)` to `crates/fuse/src/platform/linux.rs`
  (next to `unmount_filesystem`) so the `/proc/self/mountinfo` parse + `fusermount3 -u`/`-z` logic is
  unit-testable in isolation and keeps Tauri glue thin. Call it from `mount_filesystem` under
  `#[cfg(target_os = "linux")]`.
- Reuse the existing `fusermount3`/`fusermount` cascade; just add the `-z` lazy fallback for the
  disconnected case.
- Secondary (todo's "less alarming copy"): soften the notification string. Optional, low priority.

### Risk

LOW. Linux-only, additive, no change to macOS/Windows paths. The `/proc/self/mountinfo` parse must
handle the mount path containing spaces (mountinfo escapes them as `\040`) — use a tolerant
substring/field check. `fusermount3 -z` (lazy) can leave the old session detaching in the background;
that is acceptable since we immediately mount a fresh session at the same path.

### Test

- Unit: a `/proc/self/mountinfo` parser fed fixture lines (mount present / absent / path-with-spaces)
  → returns correct "is mounted" boolean. Pure, no root needed.
- Unit: EEXIST → recover-then-retry decision logic (mock the unmount call behind a closure/trait).
- E2E/manual ONLY (cannot unit-test a real mount): on Linux, SIGKILL the app mid-mount, relaunch,
  assert the vault remounts without the "mount failed" notification. This is the Phase-43 Linux UAT
  recipe; flag as manual.

## Requirement 4: Park legacy empty file_meta_ipns_name replay entries

### Current Behavior (file:line)

`replay_upload_entry` in `crates/fuse/src/lib.rs:1828-2012`. When `file_meta_ipns_name` is `None`
(legacy pre-Phase-45 `""` sentinel, mapped to `None` by `deser_opt_string` in `queue.rs:22-25`):

- Step 3 (`lib.rs:1899-1984`) is guarded by `if let Some(file_ipns_key_hex_str) = file_ipns_key_hex`
  and `if let Some(file_meta_ipns_name) = file_meta_ipns_name` — so with `None` name, the per-file IPNS
  publish is **skipped**.
- Step 4 (`lib.rs:1986-2001`) still builds a `FolderChild::File` `FilePointer` with
  `file_meta_ipns_name = file_meta_ipns_name.unwrap_or_default()` = `""` (`lib.rs:1990, 1995`) and
  `id = format!("replay-{}", "")` = `"replay-"` (`lib.rs:1993`).
- `fetch_merge_publish_parent` (`lib.rs:2003`) publishes that pointer into the parent. Back in
  `replay_for_vault`, `Ok(())` → `journal.remove(&entry.id)` (`lib.rs:1331`). The entry is marked
  successfully replayed.

Consequence (todo): a content CID with no resolvable per-file metadata record, and multiple empty-name
entries collide under `merge_folder_children`'s `child_ipns_key` keying (`lib.rs:344-348`,
`file_meta_ipns_name.as_str()` = `""` for all of them → they all map to the same HashMap key
`lib.rs:351-355`, so only one survives the merge).

`replay_for_vault` decides remove-vs-retain purely on the `Result`: `Ok(())` → `remove`
(`lib.rs:1325-1332`), `Err(e)` → `record_failure` which retains/parks (`lib.rs:1333-1351`,
`queue.rs:283-303`).

### Minimal Change (recommend: PARK)

Make `replay_upload_entry` return `Err` for the legacy `None`-name case BEFORE Step 4 builds the empty
FilePointer. Insert immediately after Step 3 (after `lib.rs:1984`), before Step 4:

```rust
// Park legacy entries with no per-file IPNS name rather than publishing an empty,
// unresolvable FilePointer (id "replay-", file_meta_ipns_name ""). Returning Err
// routes through record_failure → retained on disk; it never marks the entry as
// successfully replayed. (No fresh-IPNS minting — lowest risk, no new key material.)
if file_meta_ipns_name.is_none() {
    return Err(
        "legacy UploadFile entry has no per-file IPNS name — parking (no empty FilePointer)"
            .to_string(),
    );
}
```

Why PARK over mint-fresh-IPNS:

- Minting a fresh per-file IPNS name+key changes the stored metadata shape and adds key material +
  TEE enrollment to a recovery path, with no user to confirm the new identity. Higher blast radius.
- Parking is a pure control-flow change: the entry is retained, accumulates retries, and eventually
  parks as `Failed` at `max_retries` (D-09), surfacing a `WriteParked` notification for manual
  intervention. No new crypto, no schema change.

Caveat the plan must address (from the todo): **already-published empty-locator FilePointers from past
replays.** Parking new replays does not clean up `"replay-"`/`""` pointers already merged into parent
metadata. Decide: (a) leave them (they are content-resolvable via CID but lack per-file metadata —
acceptable, pre-existing) or (b) add a one-time sweep. Recommend (a) — document as known residue;
do not expand scope into a metadata migration.

### Risk

MEDIUM — this is a crash-recovery behavior change. The new `Err` path must not be reachable for the
normal (`Some`-name) case. Guard precisely on `file_meta_ipns_name.is_none()`. The existing
`replay_for_vault_does_not_touch_failed_entries` test (`lib.rs:2102`) must still pass.

### Test

- Unit (`#[tokio::test]`): Step 1 uploads ciphertext first, so use the unroutable API
  `http://127.0.0.1:1` and assert the entry is RETAINED after `replay_for_vault`, not removed. Build a
  `JournalOp::UploadFile` with `file_meta_ipns_name: None`; run `replay_for_vault`; assert
  `load_all_for_vault().len() == 1` (mirrors the existing characterization test at `lib.rs:2102`). If
  the park check is moved above Step 1, no network is needed at all.
- Unit: `merge_folder_children` with two `FilePointer`s both having `file_meta_ipns_name: ""` →
  document/assert the collision (pins the motivation; the parking fix prevents new ones).

## Requirement 5: Strict (cache-bypassing) IPNS resolve in replay classification

### Current Behavior (file:line)

`resolve_ipns_for_replay` (`crates/fuse/src/lib.rs:211-217`) calls
`coordinator.resolve_sequence(api, ipns_name)` and pipes the `Result<u64, String>` through
`classify_resolve_outcome` (`lib.rs:227-236`).

`PublishCoordinator::resolve_sequence` (`lib.rs:262-299`) on resolve `Err` falls back to the cache:

```rust
Err(e) => match self.get_cached(ipns_name) {                 // :283
    Some(cached) => { log::warn!(...); Ok(cached) }          // :284-291  ← transient failure → Ok(cached)
    None => Err(format!("IPNS resolve failed and no cached sequence ...")), // :293-296
},
```

So a transient (non-404) failure WITH a cached value returns `Ok(cached)` →
`classify_resolve_outcome(Ok(cached))` → `IpnsResolveOutcome::Found(cached)` (`lib.rs:230`) → replay
treats it as "record exists, not first publish" (`lib.rs:1941`) and publishes at `cached + 1` instead
of parking. A network blip thus advances the sequence off a stale cached value rather than retaining
the entry.

`classify_resolve_outcome` is unit-pinned by `classify_resolve_outcome_maps_resolve_results`
(`lib.rs:2057-2094`) — that test asserts `Ok(seq)→Found`, not-found/404→`NotFound`,
other-err→`Error`. It must not regress.

### Minimal Change (recommend: add `resolve_sequence_strict`)

Add a cache-bypassing method on `PublishCoordinator` and call it from `resolve_ipns_for_replay` only.
This keeps the cache-fallback behavior for the LIVE publish path (`spawn_metadata_publish` at
`lib.rs:401`, mkdir at `write_ops.rs:629`) unchanged — those WANT cache resilience — while the REPLAY
classification path becomes strict.

Add after `resolve_sequence` (`lib.rs:299`):

```rust
/// Strict resolve for replay classification: returns Err on ANY resolve failure,
/// never falling back to the cache. A genuine success still updates+returns the
/// max(resolved, cached) sequence so a subsequent confirmed publish advances correctly.
pub async fn resolve_sequence_strict(
    &self,
    api: &cipherbox_api_client::ApiClient,
    ipns_name: &str,
) -> Result<u64, String> {
    let resp = cipherbox_api_client::ipns::resolve_ipns(api, ipns_name)
        .await
        .map_err(|e| format!("IPNS resolve failed for {}: {}", ipns_name, e))?;
    let resolved = resp.sequence_number.parse::<u64>().unwrap_or(0);
    let cached = self.get_cached(ipns_name).unwrap_or(0);
    let seq = std::cmp::max(resolved, cached);
    self.update_cache(ipns_name, seq);
    Ok(seq)
}
```

Then change `resolve_ipns_for_replay` (`lib.rs:216`):

```rust
classify_resolve_outcome(coordinator.resolve_sequence_strict(api, ipns_name).await)
```

Now a transient non-404 resolve `Err` → `classify_resolve_outcome(Err(...))` →
`IpnsResolveOutcome::Error(e)` (`lib.rs:234`) → replay returns Err (`lib.rs:1949-1954`) → entry
retained. A real 404 still classifies `NotFound` → first publish. `classify_resolve_outcome` is
unchanged, so its characterization test does not regress.

This is lower-risk than rewriting `resolve_ipns_for_replay` to call `resolve_ipns` directly and
re-classify inline, because the brittle 404-substring contract stays centralized in the already-tested
`classify_resolve_outcome`.

### Risk

MEDIUM — crash-recovery behavior change. The risk is over-parking: a flaky network now retains entries
that previously published off cache. That is the INTENDED safer behavior (retry next mount), and
`record_failure` still parks at `max_retries` (D-09). Must NOT touch the live publish path's
`resolve_sequence` (those rely on cache fallback during normal operation).

### Test

- Unit (pure): classification is unchanged, so no new classify test needed. Add a test that
  `resolve_sequence_strict` returns `Err` when `resolve_ipns` errors even with a populated cache —
  pre-seed via `record_publish`, point at unroutable `http://127.0.0.1:1`, assert `Err` (cache present
  but bypassed).
- Characterization: transient-failure-with-cache → `replay_for_vault` retains the entry (len stays 1);
  real 404 → first publish path taken. The 404 leg needs a mock returning 404 or is E2E.
- Regression: `classify_resolve_outcome_maps_resolve_results` (`lib.rs:2057`) must still pass.

## Requirement 6: read_ops/write_ops handler test harness + journal_helpers tests

### Current Behavior (file:line)

Every handler in `crates/fuse/src/read_ops.rs` / `write_ops.rs` lives in
`pub(crate) mod implementation` gated `#[cfg(feature = "fuse")]` (`read_ops.rs:6-7`) and consumes a
concrete `fuser::Reply*` value (e.g. `handle_getattr(fs, ino, reply: ReplyAttr)` at `read_ops.rs:249`;
full list at `read_ops.rs:89-1005` and `write_ops.rs:21-869`).

The only constructor for a reply is the `Reply` trait method `fn new<S: ReplySender>(unique, sender)`
(`vendor/fuser/src/reply.rs:50-53`, impls e.g. `ReplyEmpty` at `:118-124`, `ReplyAttr` at `:209`,
`ReplyEntry` at `:175`, `ReplyXattr` at `:640`). `Reply` IS re-exported
(`vendor/fuser/src/lib_impl.rs:28` `pub use reply::{Reply, ReplyAttr, ReplyData, ReplyEmpty,
ReplyEntry, ReplyOpen};`), but `ReplySender` (`reply.rs:35`) is **NOT** re-exported, and
`mod reply;` is private (`lib_impl.rs:45`). So cipherbox-fuse cannot name `ReplySender` and cannot
implement a capturing sender → cannot build reply objects in unit tests. This is the BLOCKER.

The `ReplySender` trait (`reply.rs:35-41`) requires only:

```rust
pub trait ReplySender: Send + Sync + Unpin + 'static {
    fn send(&self, data: &[IoSlice<'_>]) -> std::io::Result<()>;
    #[cfg(feature = "abi-7-40")]
    fn open_backing(&self, fd: BorrowedFd<'_>) -> std::io::Result<BackingId>;
}
```

The `abi-7-40` feature is NOT enabled — both `crates/fuse/Cargo.toml:33` and
`apps/desktop/src-tauri/Cargo.toml:55` use `fuser = { version = "0.16", default-features = false,
features = ["libfuse"] }`, and vendored `default = []` (`vendor/fuser/Cargo.toml:62`). So a test sender
only implements `send`.

### Vendored fuser ReplySender export

The minimal vendored-crate edit (does NOT touch the FUSE-T `channel.rs` patch):

In `apps/desktop/src-tauri/vendor/fuser/src/lib_impl.rs`, the current line 28 is:

```rust
pub use reply::{Reply, ReplyAttr, ReplyData, ReplyEmpty, ReplyEntry, ReplyOpen};
```

Add a `ReplySender` export — append one new line after `:28`:

```rust
pub use reply::ReplySender;
```

One added `pub use` line. `mod reply;` stays private; only the trait name is surfaced. No behavior
change, no impact on `channel.rs` or any abi-gated code.

### make_test_fs() recipe

`CipherBoxFS` (`crates/fuse/src/lib.rs:665-702`) has 29 fields. A test builder, placed in a
`#[cfg(all(test, feature = "fuse"))]` module in cipherbox-fuse (so handlers and `fuser` types are in
scope), built inside a `#[tokio::test]` (for `Handle::current()`):

```rust
fn make_test_fs() -> CipherBoxFS {
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc::channel;
    use zeroize::Zeroizing;

    let journal_dir = std::env::temp_dir()
        .join("cb-test-journal")
        .join(format!("{}-{}", std::process::id(), /* unique per test */ 0u64));
    std::fs::create_dir_all(&journal_dir).unwrap();

    let (refresh_tx, refresh_rx) = channel();
    let (content_tx, content_rx) = channel();
    let (filepointer_tx, filepointer_rx) = channel();
    let (upload_tx, upload_rx) = channel();

    let mut inodes = crate::inode::InodeTable::new(); // root inode ino=1 pre-created (inode.rs:198)
    // Root must carry ipns_name + ipns_private_key for build_folder_metadata / journal builders.
    if let Some(root) = inodes.get_mut(crate::inode::ROOT_INO) {
        root.kind = crate::inode::InodeKind::Root {
            ipns_name: Some("k51test-root".to_string()),
            ipns_private_key: Some(Zeroizing::new(vec![0u8; 32])),
        };
    }

    CipherBoxFS {
        inodes,
        metadata_cache: crate::cache::MetadataCache::new(),
        content_cache: crate::cache::ContentCache::new(),
        api: std::sync::Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1")),
        private_key: Zeroizing::new(vec![0u8; 32]),
        public_key: Zeroizing::new(vec![0u8; 33]), // secp256k1 compressed pubkey = 33 bytes
        root_folder_key: Zeroizing::new(vec![0u8; 32]),
        root_ipns_name: "k51test-root".to_string(),
        rt: tokio::runtime::Handle::current(),
        next_fh: AtomicU64::new(1),
        open_files: HashMap::new(),
        temp_dir: std::env::temp_dir().join("cipherbox-test"),
        tee_public_key: None,
        tee_key_epoch: None,
        max_versions_per_file: 5,
        version_cooldown_ms: 0,
        refresh_rx, refresh_tx,
        mutated_folders: HashMap::new(),
        prefetching: HashSet::new(),
        refreshing_metadata: HashSet::new(),
        content_rx, content_tx,
        filepointer_rx, filepointer_tx,
        resolving_file_pointers: HashSet::new(),
        pending_content: HashMap::new(),
        upload_rx, upload_tx,
        publish_coordinator: std::sync::Arc::new(crate::PublishCoordinator::new()),
        publish_queue: HashMap::new(),
        journal: cipherbox_sdk::WriteQueue::new(journal_dir, 5),
    }
}
```

Field-by-field notes (anchored to the real struct literal in `apps/desktop/src-tauri/src/fuse/mod.rs:267-291`):

- `public_key` must be 33 bytes (secp256k1 compressed) — ECIES `wrap_key` in the journal builders
  (`journal_helpers.rs:150, 281, 295`) expects a valid EC public key. A 33-byte zero vec is NOT a valid
  curve point; for builder tests that call `wrap_key`, generate a real keypair via
  `cipherbox_crypto::generate_ec_keypair` (or the project's EC keygen) instead of zeros. For
  metadata-only handler tests (getattr/access/lookup/unlink/rmdir/rename/flush/xattr) that never wrap
  keys, zeros are fine.
- `rt: tokio::runtime::Handle::current()` requires the test be `#[tokio::test]` (or
  `#[tokio::test(flavor = "multi_thread")]` if a handler spawns and you await drain).
- `journal_dir` must exist before `WriteQueue::new` (constructor does not create it — `queue.rs:157`).
  Use a per-test unique subdir and clean it up at the end (mirror the existing tests'
  `std::env::temp_dir().join(...).join(format!("{}", std::process::id()))` pattern at `lib.rs:2106`).
- Root inode at `ROOT_INO = 1` is auto-created by `InodeTable::new()` (`inode.rs:43, 198`); override
  its `kind` via `get_mut(ROOT_INO)` to inject `ipns_name`/`ipns_private_key` (matches the desktop
  mount glue at `mod.rs:138-143`).

### Capturing ReplySender + handler test pattern

```rust
use std::io::IoSlice;
use std::sync::{Arc, Mutex};
use fuser::{Reply, ReplyEmpty, ReplyAttr, ReplyEntry};

#[derive(Clone)]
struct CaptureSender(Arc<Mutex<Vec<u8>>>);

impl fuser::ReplySender for CaptureSender {
    fn send(&self, data: &[IoSlice<'_>]) -> std::io::Result<()> {
        let mut buf = self.0.lock().unwrap();
        for slice in data { buf.extend_from_slice(slice); }
        Ok(())
    }
}

// Wire format (vendor/fuser/src/ll/fuse_abi.rs:932-936, with_iovec at ll/reply.rs:38-48):
//   fuse_out_header = { len: u32 LE, error: i32 LE, unique: u64 LE }  (16 bytes total)
// error == 0 → success; error == -errno → failure.
fn reply_error_code(captured: &Arc<Mutex<Vec<u8>>>) -> i32 {
    let buf = captured.lock().unwrap();
    assert!(buf.len() >= 16, "out-header is 16 bytes");
    i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) // error field at byte offset 4
}
```

Then for a metadata-only handler:

```rust
#[tokio::test]
async fn getattr_returns_ok_for_root() {
    let mut fs = make_test_fs();
    let cap = Arc::new(Mutex::new(Vec::new()));
    let reply = <ReplyAttr as Reply>::new(/*unique*/ 1, CaptureSender(cap.clone()));
    crate::read_ops::implementation::handle_getattr(&mut fs, crate::inode::ROOT_INO, reply);
    assert_eq!(reply_error_code(&cap), 0);
}
```

Handlers safely unit-testable WITHOUT network (per the todo's Option A list): `handle_getattr`
(`read_ops.rs:249`), `handle_access` (`:983`), `handle_lookup` incl `"."`/`".."` (`:122`),
`handle_getxattr`/`handle_listxattr` (`:993`/`:1005`), `handle_flush` (`:978`), `handle_setattr`
truncate (`write_ops.rs:21`), `handle_create` (`:140`), `handle_unlink` (`:280`), `handle_rmdir`
(`:704`), `handle_rename` (`:869`), `handle_mkdir` happy-path (`:440` — uses a real temp `WriteQueue`
dir; the detached publish thread will fail against `127.0.0.1:1` but `journal.put` + reply happen
synchronously before the spawn). Leave network-blocking `handle_read` (`:478`) and `handle_open`
(`:264`, fires async prefetch) to E2E.

`journal_helpers` builder tests are pure-synchronous and need only `make_test_fs` + a real EC keypair:
`build_upload_journal_entry` (`journal_helpers.rs:128`), `build_mkdir_journal_entry` (`:378`), and the
free helpers `wrap_key_to_hex` (`:477`), `generate_entry_id` (`:467`), `current_unix_ms` (`:458`).
Note `generate_entry_id`/`current_unix_ms`/`wrap_key_to_hex` are module-private free fns — test them
via a `#[cfg(test)] mod tests` inside `journal_helpers.rs` itself (the existing empty module at
`journal_helpers.rs:486-493`), or make them `pub(crate)`.

### Risk

LOW-MEDIUM. The vendored edit is one `pub use` line. The harness risk is the detached upload threads in
`handle_release`/`handle_mkdir`/`handle_create` racing test teardown — they target `127.0.0.1:1` and
fail fast, calling `record_failure` which writes to the journal dir. Tests must not assert journal
emptiness without accounting for the retained entry, and must clean the per-test journal dir. Use
`#[tokio::test(flavor = "multi_thread")]` and a brief drain if asserting post-spawn state.

### Test

This requirement IS the test infrastructure. Its own "proof" is that the new handler unit tests
compile and pass (e.g. `getattr_returns_ok_for_root`, `unlink_nonexistent_returns_enoent`,
`flush_returns_ok`, `mkdir_happy_path_puts_journal_entry_then_replies_entry`) plus the journal_helpers
builder round-trip tests.

## Validation Architecture

### Test Framework

| Property | Value |
| -------- | ----- |
| Framework | Rust built-in `#[test]` / `#[tokio::test]` (tokio dev-dep already used, e.g. `lib.rs:2101`) |
| Config file | none — Cargo workspace; per-crate `[dev-dependencies]` |
| Quick run command | `cargo test -p cipherbox-fuse --features fuse <test_name>` |
| Full suite command | `cargo test -p cipherbox-fuse --features fuse` and `cargo test -p cipherbox-sdk` |

> Constraint (from project memory): GSD sub-agents must NOT run full concurrent Rust test suites (RAM
> starvation). Run single named tests during development; reserve the full suite for the phase gate.

### Phase Requirements to Test Map

| Req | Behavior | Test Type | Command | Unit-testable now? |
| --- | -------- | --------- | ------- | ------------------ |
| 1 | mkdir conflict re-arms parent publish | characterization (in-memory `FsEvent`) | `cargo test -p cipherbox-fuse --features fuse mkdir_conflict_rearms` | needs req-6 harness for full handler; the `FsEvent` drain test is pure |
| 1 | mkdir happy-path journals before reply | unit | `... mkdir_happy_path_*` | needs req-6 harness |
| 2 | release journals ciphertext before temp cleanup | unit | `... release_journals_before_cleanup` | needs req-6 harness + temp journal dir |
| 2 | replay re-uploads journaled ciphertext | characterization | `... replay_reuploads_ciphertext` | yes (pure WriteQueue round-trip) |
| 2 | flush is a no-op OK | unit | `... flush_returns_ok` | needs req-6 harness |
| 3 | mountinfo parser detects stale mount | unit | `... mountinfo_detects_stale` | yes (pure parser) |
| 3 | EEXIST → recover-then-retry decision | unit | `... eexist_triggers_recovery` | yes (mock unmount closure) |
| 3 | real Linux remount after SIGKILL | E2E/manual | Linux UAT recipe | NO — manual only |
| 4 | legacy None-name entry is parked, not removed | characterization | `... legacy_empty_name_parks` | yes (unroutable API, assert retained) |
| 4 | empty-name FilePointers collide in merge | unit | `... empty_name_merge_collision` | yes (pure `merge_folder_children`) |
| 5 | `resolve_sequence_strict` errs despite cache | unit | `... strict_resolve_bypasses_cache` | yes (unroutable API + seeded cache) |
| 5 | transient failure retains replay entry | characterization | `... transient_failure_retains_entry` | yes (unroutable API) |
| 5 | `classify_resolve_outcome` unchanged | regression | `... classify_resolve_outcome_maps_resolve_results` | yes (already exists, `lib.rs:2057`) |
| 6 | handler harness compiles + sample handlers pass | unit | `... getattr_returns_ok_for_root` etc. | this IS the deliverable |

### Sampling Rate

- Per task commit: the single named test(s) for that task (`cargo test -p <crate> --features fuse <name>`).
- Per wave merge: `cargo test -p cipherbox-fuse --features fuse` + `cargo test -p cipherbox-sdk`
  (run sequentially, not concurrently — RAM constraint).
- Phase gate: full fuse + sdk suites green before `/gsd-verify-work`; Linux remount verified manually
  via the headless desktop FUSE UAT recipe.

### Wave 0 Gaps

- [ ] Vendored fuser `pub use reply::ReplySender;` (`vendor/fuser/src/lib_impl.rs:28`) — blocks ALL
      handler unit tests (req 1, 2, 6). Land FIRST.
- [ ] `make_test_fs()` + `CaptureSender` test support module in cipherbox-fuse — shared fixture for
      every handler test.
- [ ] No new framework install — Rust test harness + tokio dev-dep already present.

## Project Constraints (from CLAUDE.md)

- Rust-only phase; TypeScript out of scope. (Use string-literal style where it maps; this is Rust.)
- Single-thread FUSE constraint (apps/desktop/CLAUDE.md): NEVER block FUSE callbacks on network I/O;
  `release()` spawns a detached upload thread; durability comes from the out-of-callback journal.
- Vendored fuser has a critical `channel.rs:receive()` FUSE-T patch — any vendored edit must be minimal
  and must not disturb `channel.rs`. The req-6 edit is one `pub use` line in `lib_impl.rs`, untouched
  `channel.rs`.
- Security rules: never log/store/transmit unencrypted keys; journal stores only ciphertext +
  ECIES-wrapped keys (`queue.rs:6-7`, enforced today). Preserve this — no plaintext in the journal.
- Terminology: `ipnsName`, `ipnsRecord`, `privateKey`, `publicKey`, `folderKey`, `fileKey`,
  `rootFolderKey`, `keyEpoch`, `teePublicKey` (these map to the Rust field names already in use).
- Git: feature branch `feat/{slug}`, conventional commits, no parens in subject line.
- Markdownlint enforced on commit for this file: `###` headings (not bold-as-heading), blank lines
  around code blocks and lists, no italic "Last updated" footer.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
| ------- | ----------- | ----------- | --- |
| Durable pending-upload queue | A new memory/disk queue | existing `cipherbox_sdk::WriteQueue` (`crates/sdk/src/queue.rs`) | Already fsync-durable, vault-scoped, retry/park-aware (D-04/D-09) |
| FUSE reply construction in tests | A from-scratch mock fuser | the vendored `Reply::new` + a tiny `ReplySender` impl | Reply types are already exported; only `ReplySender` needs surfacing |
| IPNS resolve + classify | Inline `.contains("not found")` | `classify_resolve_outcome` + new `resolve_sequence_strict` | Centralizes the brittle 404 substring contract; already unit-pinned |
| Linux unmount | Raw `umount` syscall | extend existing `platform/linux.rs::unmount_filesystem` cascade with `-z` | Reuses the fusermount3/fusermount/umount fallback ladder |
| Mountpoint detection | `path.exists()` | parse `/proc/self/mountinfo` | `exists()` returns false for ENOTCONN disconnected mounts (the root cause) |

## Common Pitfalls

### Pitfall 1: "Fixing" requirement 1/2 by rewriting already-correct code

**What goes wrong:** Reintroducing a warn-only mkdir arm or blocking release on the network.
**Why it happens:** The 2026-06-11 todos describe pre-Phase-43 state; the bugs are already fixed.
**How to avoid:** Diff current `write_ops.rs:670-679` and `read_ops.rs:814-884` against the todo claims
first; scope to verification + tests.
**Warning signs:** A plan task that says "add queue_publish to the conflict arm" — it's already there
via `FsEvent::MkdirConflict` → `lib.rs:932`.

### Pitfall 2: Regressing D-04 journal-before-ack

**What goes wrong:** Moving `reply.ok()` before `journal.put`, or removing `handle.cleanup()` ordering.
**Why it happens:** Reordering to "simplify" release.
**How to avoid:** Keep `journal.put` (`read_ops.rs:815`) strictly before any in-memory mutation,
`handle.cleanup`, and `reply.ok`. Add a characterization test that fails if reply precedes journal.

### Pitfall 3: Strict-resolve over-reaching into the live publish path

**What goes wrong:** Replacing `resolve_sequence` (live path) with the strict variant, breaking
normal-operation cache resilience.
**How to avoid:** Add `resolve_sequence_strict` as a NEW method; call it ONLY from
`resolve_ipns_for_replay` (`lib.rs:216`). Leave `spawn_metadata_publish`/mkdir using `resolve_sequence`.

### Pitfall 4: Parking req-4 entries but still uploading ciphertext first

**What goes wrong:** `replay_upload_entry` uploads ciphertext (Step 1, `lib.rs:1872`) BEFORE the
parking check, so a parked legacy entry still re-pins content each mount.
**How to avoid:** Acceptable (idempotent CID, content is wanted), but if churn matters, move the
`file_meta_ipns_name.is_none()` park check ABOVE Step 1. Document the choice.

### Pitfall 5: Test journal dirs colliding across concurrent tests

**What goes wrong:** Shared temp journal dir → cross-test entry contamination.
**How to avoid:** Per-test unique subdir (`process::id()` + test-unique suffix), cleaned at end —
mirror `lib.rs:2106-2110`.

## Runtime State Inventory

> This phase changes crash-recovery code paths but does NOT rename/migrate stored data. Inventory of
> what on-disk/runtime state the changes touch:

| Category | Items Found | Action Required |
| -------- | ----------- | --------------- |
| Stored data | On-disk journal entries at `default_journal_dir()` = `<data_local>/cipherbox/cb-journal/*.json` (`mod.rs:62-70`). Req-4/5 change which entries get REMOVED vs RETAINED. Legacy `""`-sentinel entries already deserialize via `deser_opt_string` (`queue.rs:22`). | Code change only — no journal schema migration. New parked entries accumulate as `Failed` (D-09). |
| Live service config | None — no external service config carries renamed strings. | None |
| OS-registered state | Linux FUSE mount at `~/CipherBox` (`mount_point()`). Req-3 detects/unmounts stale mounts; no persistent registration changes. | Runtime unmount via `fusermount3` — no persisted state. |
| Secrets/env vars | None renamed. IPNS keys remain ECIES-wrapped in journal/metadata. | None |
| Build artifacts | Vendored fuser crate gets one `pub use` line; consumers recompile. No artifact rename. | Recompile only. |

**Already-published empty-locator FilePointers (req 4):** pre-existing residue in parent metadata from
past replays — NOT auto-cleaned. Decide leave-vs-sweep (recommend leave + document).

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
| ---------- | ----------- | --------- | ------- | -------- |
| Rust toolchain / cargo | all build+test | ✓ (assumed) | workspace MSRV | — |
| `fusermount3` | req-3 Linux stale-mount recovery | Linux-only (target machine) | libfuse3 | `fusermount` then `umount` (existing cascade) |
| `/proc/self/mountinfo` | req-3 stale detection | Linux-only | — | EEXIST fall-through path |
| Live IPNS/IPFS API | E2E only (not unit) | staging API | — | unit tests use unroutable `http://127.0.0.1:1` |

**Missing with no fallback:** none for unit work. The real Linux mount (req-3 E2E) requires a Linux
host with libfuse3 — manual UAT only, not gateable in CI unit tests.

## Security Domain

`security_enforcement` is absent in `.planning/config.json` → enabled.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
| ------------- | ------- | ---------------- |
| V2 Authentication | no | Phase does not touch auth |
| V3 Session Management | no | — |
| V4 Access Control | no | FUSE access() always grants (encryption is the access control, per apps/desktop/CLAUDE.md) |
| V5 Input Validation | yes | Journal JSON parse is skip-with-warn, never panics (`queue.rs:248-255`); preserve |
| V6 Cryptography | yes | ECIES `wrap_key`/`unwrap_key`, AES-256-GCM — never hand-roll; journal stores ciphertext + ECIES-wrapped keys only |
| V7 Error Handling/Logging | yes | Never log plaintext/raw keys; `sanitize_error` scrubs paths/tokens (`crates/sdk/src/sync.rs`) |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
| ------- | ------ | ------------------- |
| Plaintext leaking into journal | Information Disclosure | Journal references `ciphertext_b64` only (`journal_helpers.rs:14-17, 286`); preserve invariant |
| Raw key written to disk | Information Disclosure | Keys ECIES-wrapped once before journalling (`journal_helpers.rs:18, 477`); test sender/test data must not introduce raw keys |
| Journal file readable by other users | Information Disclosure | 0o600 set atomically at create (`queue.rs:177-182`); journal dir 0o700 (`mod.rs:133`) |
| Replay double-publish / sequence regression | Tampering | req-5 strict resolve prevents advancing off stale cache; CAS `expected_sequence_number` on publish |
| Test threads writing to real journal dir | Tampering | per-test isolated temp journal dir; never point tests at `default_journal_dir()` |

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
| --- | ----- | ------- | ------------- |
| A1 | secp256k1 compressed public key is 33 bytes and `wrap_key` needs a valid curve point | Req 6 make_test_fs | Builder tests calling `wrap_key` with zero pubkey fail; use a real keypair (metadata-only handler tests unaffected) |
| A2 | The debounced parent republish (after MkdirConflict re-arm) does a fetch-and-merge, not a blind overwrite | Req 1 | If it blind-overwrites, a concurrent remote parent edit is clobbered — a latent bug to fix; plan must verify against the debounced publisher code |
| A3 | `abi-7-40` feature stays disabled, so `ReplySender::open_backing` need not be implemented in the test sender | Req 6 | If enabled later, the test sender must also impl `open_backing`; gate with the same cfg |
| A4 | Replay re-upload is fully idempotent including the versioning path (`apply_versioning`) | Req 2 | A non-idempotent version append on replay could double-append; verify `apply_versioning` keying |
| A5 | Leaving already-published empty-locator FilePointers in place is acceptable | Req 4 | If they cause user-visible breakage, a one-time metadata sweep is needed (scope expansion) |

## Open Questions

1. **Does the debounced publisher merge remote parent children before republish?** (A2)
   - What we know: the mkdir spawn conflict path does NOT merge; it re-arms the debounce.
   - What's unclear: whether `flush_publish_queue`'s actual publish does fetch-and-merge like
     `spawn_metadata_publish` (`lib.rs:440-527`) does.
   - Recommendation: planner adds a verification task to read the debounced publish implementation.
2. **Flush durability window policy (req 2).**
   - What we know: `flush` is a no-op; durability is on `release`.
   - What's unclear: whether closing the flush-before-release window is in scope.
   - Recommendation: document as accepted limitation unless the user requires otherwise; do not regress
     D-04 to close it.
3. **Cleanup of pre-existing empty-locator FilePointers (req 4).** Leave vs sweep — recommend leave +
   document; confirm with user in discuss-phase.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
| ------------ | ---------------- | ------------ | ------ |
| Memory-only `WriteQueue` (VecDeque) lost on quit | Fsync-durable disk journal (`queue.rs`) | Phase 43 | Releases survive crash; req-2 todo is mostly obsolete |
| mkdir conflict warn-only | `FsEvent::MkdirConflict` re-arm + retained journal entry | Phase 43 (D-11a/b) | req-1 todo mostly obsolete |
| `""` sentinel for file_meta_ipns_name | `Option<String>` + `deser_opt_string` compat | Phase 45 (#18) | req-4/5 are the residual cleanup of behavior preserved through #18/#19 |
| `.contains("not found")` inline classify | typed `IpnsResolveOutcome` + `classify_resolve_outcome` | Phase 45 (#19) | req-5 builds on this; must not regress its test |

**Deprecated/outdated:**

- The line numbers in the 2026-06-11 and Phase-43 todos (`write_ops.rs:601-610`,
  `windows/write_ops.rs:194`, `read_ops.rs:852`, `mod.rs:65-86`): the files have shifted; use the
  anchors in THIS document.

## Sources

### Primary (HIGH confidence)

- `crates/fuse/src/lib.rs` — PublishCoordinator (`:240-316`), resolve_ipns_for_replay (`:211`),
  classify_resolve_outcome (`:227`), replay_for_vault (`:1179`), replay_upload_entry (`:1828`),
  CipherBoxFS struct (`:665`), MkdirConflict handler (`:927`), existing tests (`:2033-2169+`)
- `crates/fuse/src/read_ops.rs` — handle_release (`:773`), handle_flush (`:978`), handler list
- `crates/fuse/src/write_ops.rs` — handle_mkdir conflict arm (`:670`), journal-before-reply (`:555`)
- `crates/fuse/src/platform/windows/write_ops.rs` — mkdir conflict (`:261`), release (`:837`)
- `crates/fuse/src/journal_helpers.rs` — builders + free helpers + UploadJournalResult
- `crates/sdk/src/queue.rs` — WriteQueue, JournalEntry/JournalOp, deser_opt_string, record_failure
- `crates/fuse/src/error.rs` — IpnsResolveOutcome enum
- `crates/fuse/src/platform/linux.rs` — unmount_filesystem cascade
- `apps/desktop/src-tauri/src/fuse/mod.rs` — mount_filesystem, stale-mount branch, CipherBoxFS literal
- `apps/desktop/src-tauri/vendor/fuser/src/{lib.rs,lib_impl.rs,reply.rs,ll/reply.rs,ll/fuse_abi.rs}` —
  re-export structure, ReplySender trait, Reply::new, wire format
- `crates/fuse/Cargo.toml`, `apps/desktop/src-tauri/Cargo.toml`, `vendor/fuser/Cargo.toml` — features
- `CLAUDE.md`, `apps/desktop/CLAUDE.md` — single-thread constraint, vendored patch, security rules

### Secondary (MEDIUM confidence)

- `.planning/todos/pending/*` — the six source todos (note: several describe pre-Phase-43/45 state)

## Metadata

**Confidence breakdown:**

- Req 1 (already fixed): HIGH — verified both platform conflict arms + event handler in source
- Req 2 (already durable): HIGH — verified journal-before-cleanup ordering and ciphertext capture
- Req 3 (Linux stale-mount): HIGH — root cause + existing unmount helper confirmed in source
- Req 4 (park legacy): HIGH — exact code path and remove-vs-retain decision confirmed
- Req 5 (strict resolve): HIGH — cache-fallback path and call site confirmed
- Req 6 (test harness): HIGH — ReplySender gate, wire format, full field list all confirmed in source

**Research date:** 2026-06-15
**Valid until:** 2026-07-15 (stable Rust internals; re-verify line anchors if the crate is refactored)
