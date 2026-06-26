# Phase 52: Desktop FUSE Durability & At-Rest Safety - Research

**Researched:** 2026-06-19
**Domain:** Rust FUSE write-journal hardening (crates/sdk + crates/fuse + apps/desktop/src-tauri)
**Confidence:** HIGH

## Summary

Phase 52 hardens the existing durable write-journal built in Phase 43 (criticals fixed
in 45/46). The five remaining open warnings (WR-06 high, WR-07 medium, IN-03/04/05 low)
all have clear, bounded fixes anchored to existing code patterns. No protocol changes, no
new crates, no redesign — only mechanical extensions to WriteQueue, replay_for_vault,
sanitize_error, and three log call sites.

The most architecturally significant change is D-01 (WR-06): moving the ciphertext write
off the FUSE callback thread onto a background writer so that large-file operations no
longer block the filesystem. The durable-ack contract from Phase 43 (release() must not
ack until the journal entry is on disk) must be preserved via a synchronous oneshot channel
between the FUSE callback thread and the background writer.

D-04 (IN-03) requires **encryption, not omission**: both `filename` (UploadFile) and `name`
(MkdirPublish) are consumed by replay at lib.rs:2030 and lib.rs:2233 to populate
`FolderEntry.name` and `FilePointer.name` respectively. `FileMetadata` contains no
filename field. The name cannot be reconstructed from other journal data.

**Primary recommendation:** Implement in the locked sequence: D-01 (sidecar + off-thread,
biggest) → D-02 (GC + lifecycle purge) → D-03 (replay timeout + concurrent-with-mount) →
D-04 (encrypt names) → D-05/D-06 (trivial, can land in same wave as any of the above).

---

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01 (WR-06):** Sidecar `<id>.bin` for ciphertext; JSON holds path + hash + size. Heavy write +
  F_FULLFSYNC off the shared FS callback thread (background/journal-writer task). release() STILL
  awaits its own entry's durability before acking. Per-entry payload size cap.
- **D-02 (GC):** Age + size-budget GC of parked Failed entries; purge current vault's entries on
  logout; purge a vault's entries on account switch / account deletion. Planner proposes concrete
  default caps consistent with existing desktop constants.
- **D-03 (WR-07):** Wrap each replay entry's network ops in tokio::time::timeout mirroring the
  existing NETWORK_TIMEOUT discipline (sensible multiplier for large uploads) AND run replay
  concurrently with mount so mount returns immediately.
- **D-04 (IN-03):** Omit the plaintext name if replay doesn't need it; fallback: encrypt it.
  Determined during research (see below: encrypt is required).
- **D-05 (IN-04):** Extend sanitize_error scrub to cover C:\Users\ (drive-letter), /var, /tmp,
  /private.
- **D-06 (IN-05):** Replace `let _ = journal.remove(...)` with `log::warn!` at
  crates/fuse/src/lib.rs:1494,:1558 and write_ops.rs:679.

### Claude's Discretion

None — all forks were locked in the discuss phase.

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope (the FUSE-journal review warnings).

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID      | Description                                                                 | Research Support                                                                                              |
| ------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| HARD-03 | Desktop FUSE durability & at-rest safety — bound write-journal growth, stream large-file writes, add replay network timeouts, scrub at-rest plaintext filenames | All six decisions (D-01..D-06) map directly to this requirement; all are grounded in file:line evidence below |

</phase_requirements>

---

## Architectural Responsibility Map

| Capability                        | Primary Tier    | Secondary Tier      | Rationale                                                                                |
| --------------------------------- | --------------- | ------------------- | ---------------------------------------------------------------------------------------- |
| Sidecar ciphertext write (D-01)   | crates/sdk      | crates/fuse         | WriteQueue owns persistence; FUSE layer calls it via journal.put                        |
| Off-thread write + durable ack    | crates/fuse     | crates/sdk          | FUSE callback thread owns the ack; background task writes sidecar; oneshot channel bridges them |
| Per-entry size cap (D-01)         | crates/fuse     | —                   | build_upload_journal_entry (journal_helpers.rs) is where plaintext size is known        |
| GC + lifecycle purge (D-02)       | crates/sdk      | apps/desktop/tauri  | WriteQueue owns journal files; Tauri shell owns session lifecycle hooks (logout/switch)  |
| Replay timeout + concurrent (D-03)| crates/fuse     | apps/desktop/tauri  | replay_for_vault lives in crates/fuse/src/lib.rs; mount orchestration in fuse/mod.rs    |
| Name encryption (D-04)            | crates/fuse     | crates/sdk          | journal_helpers.rs builds the entry; WriteQueue stores it; replay in lib.rs consumes it |
| sanitize_error scrub (D-05)       | crates/sdk      | —                   | sync.rs:266 regex_replace_paths is the single scrub site                                 |
| Swallowed-removal log (D-06)      | crates/fuse     | —                   | lib.rs:1494/:1558 and write_ops.rs:679 are the three call sites                         |

---

## Standard Stack

### Core (no new dependencies needed)

| Library               | Version       | Purpose                                    | Why Standard                                              |
| --------------------- | ------------- | ------------------------------------------ | --------------------------------------------------------- |
| `tokio`               | workspace     | Async runtime; timeout, spawn, oneshot     | Already in crates/fuse Cargo.toml; provides `tokio::time::timeout` and `tokio::sync::oneshot` |
| `log`                 | workspace     | Logging facade for warn!/error!/info!      | Confirmed in crates/sdk/Cargo.toml:19 and crates/fuse/Cargo.toml:24 |
| `serde_json`          | workspace     | JSON serialization for journal entries     | Already used in WriteQueue::put                           |
| `cipherbox_crypto`    | workspace     | ECIES wrap_key for name encryption         | wrap_key already used at journal_helpers.rs:150            |

No new external packages are required. All capabilities needed for this phase exist in the
current workspace.

### Package Legitimacy Audit

No new packages are introduced. This section is not applicable.

---

## Architecture Patterns

### System Architecture Diagram

```
FUSE callback thread (single thread)
        |
        | release() called by OS
        v
 build_upload_journal_entry()   <-- journal_helpers.rs
        |
        | ciphertext already in memory
        v
 [D-01] Write ciphertext to <id>.bin (sidecar)
        |
        | via tokio oneshot channel to background writer task
        v
 Background journal-writer task
        |   writes sidecar <id>.bin  (streaming, off-thread)
        |   calls F_FULLFSYNC on sidecar
        |   writes/updates <id>.json (path + hash + size only)
        |   calls F_FULLFSYNC on json
        |   sends Ok/Err back via oneshot
        |
 FUSE callback thread receives oneshot reply
        |   [Ok]  -> reply.ok() to OS (durable ack preserved)
        |   [Err] -> reply.error(EIO)
        v
 Background upload thread (std::thread::spawn)
        |   reads ciphertext from sidecar <id>.bin
        |   upload_content() -> IPFS
        |   publish_file_metadata()
        |   sends UploadComplete -> FS thread
        |   (journal entry NOT removed here — replay does it)
        v
 replay_for_vault (at next mount, if crash occurred)
        |   [D-03] tokio::spawn -> runs concurrently with mount
        |   each entry: tokio::time::timeout(NETWORK_TIMEOUT * k, ...)
        |   reads ciphertext from sidecar <id>.bin
        |   re-uploads, re-publishes, removes entry on success
        v
 GC / lifecycle purge [D-02]
        |   on logout: remove all entries for current vault_root_ipns
        |   on account switch / deletion: remove entries for that vault's IPNS
        |   periodic: remove Failed entries exceeding age-window or total-size budget
```

### Recommended Project Structure (no new files needed except sidecar path changes)

```
crates/sdk/src/
├── queue.rs          # WriteQueue: add sidecar write, size cap, GC, purge methods
crates/fuse/src/
├── lib.rs            # replay_for_vault: add timeout + tokio::spawn for concurrency
│                     # lib.rs:1494,:1558: fix swallowed removals (D-06)
├── write_ops.rs      # write_ops.rs:679: fix swallowed removal (D-06)
├── journal_helpers.rs # build_upload_journal_entry: add size cap, name encryption
crates/sdk/src/
├── sync.rs           # sanitize_error/regex_replace_paths: extend scrub list (D-05)
apps/desktop/src-tauri/src/
├── commands/auth.rs  # logout(): add vault-purge call after unmount (D-02)
├── fuse/mod.rs       # mount_filesystem: replay concurrent with mount (D-03)
```

---

## Research Findings by Decision

### D-01: Sidecar + Off-Thread Write (WR-06)

**Current state (the bug):**

`queue.rs:36` — `JournalOp::UploadFile.ciphertext_b64: String` is a base64-encoded blob of
the entire AES-256-GCM ciphertext. For a 2 GB file this produces a ~2.7 GB `String` inside
`serde_json::to_vec` at `queue.rs:172-173` and then a multi-GB `write_all` + `sync_all`
executed synchronously on the FUSE callback thread at `queue.rs:188-194`.

`journal_helpers.rs:285-311` — `build_upload_journal_entry` encodes the in-memory
ciphertext to base64 at line 286 and stores it in `ciphertext_b64` inside `JournalOp::UploadFile`.
This happens synchronously on the callback thread before `journal.put` is called at
`read_ops.rs:815`.

**Phase-43 durable-ack contract (must not regress):**

`read_ops.rs:814-884` — the current flow is:
1. `journal.put(&result.entry)?` at line 815 — fsync-commits entry to disk
2. Inode mutations applied (lines 818-845)
3. `reply.ok()` at line 884 — acks the OS

The Phase-43 durable-ack invariant from 43-REVIEW.md CR-04 (fixed as confirmed in
43-REVIEW.md Post-Review Resolution): "all in-memory mutations are deferred until AFTER
the journal entry is fsynced." Moving the sidecar write off-thread means the FUSE callback
thread cannot call `reply.ok()` until it receives confirmation that the background writer
has fsynced both the `.bin` and the `.json`. This is the **oneshot channel requirement**:
the callback thread blocks on the oneshot receiver before replying to the OS.

**Recommended implementation for D-01:**

1. In `JournalOp::UploadFile`, replace `ciphertext_b64: String` with:
   - `sidecar_path: PathBuf` — absolute path to `<journal_dir>/<id>.bin`
   - `sidecar_sha256: String` — hex-encoded SHA-256 of ciphertext (integrity)
   - `size: u64` — already present

2. In `WriteQueue`, add `put_with_sidecar(entry, ciphertext: &[u8])`:
   - Streams ciphertext to `<journal_dir>/<id>.bin` in a fixed-size buffer (never allocates the full ciphertext as a `String`)
   - F_FULLFSYNC on `.bin`
   - Writes JSON entry (no ciphertext in JSON)
   - F_FULLFSYNC on `.json`
   - Returns `Ok(())` only after both fsyncs

3. In `build_upload_journal_entry` (journal_helpers.rs): add per-entry payload size cap.
   If `ciphertext.len() > MAX_JOURNAL_PAYLOAD` return `Err` so `reply.error(EIO)` is
   sent. The cap prevents OOM on very large files.

4. The sidecar write (`put_with_sidecar`) must run on a background tokio task because
   streaming a multi-GB `.bin` file on the FUSE callback thread (even without
   `serde_json::to_vec`) still blocks the thread during the write. Use:
   - `tokio::sync::oneshot::channel::<Result<JournalEntry, String>>()`
   - `rt.spawn(async move { ... put_with_sidecar ... oneshot_tx.send(...) })`
   - FUSE callback thread: `rt.block_on(oneshot_rx)` — blocks until fsync confirmed
   - On Ok: proceed with inode mutations + `reply.ok()`
   - On Err: `reply.error(EIO)` (no mutations, no stale state)

5. Background upload thread reads ciphertext from `<id>.bin` (not from `ciphertext_b64`)
   when uploading to IPFS. Remove `.bin` after successful parent-publish-gated removal of
   the `.json` entry.

**Per-entry size cap recommendation:**

No existing desktop MB constant for upload was found in the codebase. `fuser/examples/simple.rs:38`
has `MAX_FILE_SIZE = 1 TiB` (a vendor example, not a project constant). Propose
`MAX_JOURNAL_PAYLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024` (2 GiB) — at this size the
sidecar write will stall even the background task (and the OS may reject the write on low-memory
devices). Files above this cap should fail with EIO at release(), not hang.

**Key files and line numbers:** [ASSUMED — codebase reads above; no external source needed]
- `crates/sdk/src/queue.rs:34-36` — current `ciphertext_b64` field
- `crates/fuse/src/journal_helpers.rs:284-318` — `build_upload_journal_entry` where entry is constructed
- `crates/fuse/src/read_ops.rs:806-884` — current release path (CR-04 durable-ack pattern to preserve)

---

### D-02: GC + Lifecycle Purge

**Current state:**

Journal dir: `<data_local_dir>/cipherbox/cb-journal/`, created at `fuse/mod.rs:151-158`.
Single shared dir for all vaults. Vault scoping is filter-at-load-time only
(`load_all_for_vault` at `queue.rs:225-263` filters by `entry.vault_root_ipns`).
No GC, no purge-on-logout, no cross-vault cleanup.

Failed entries (`JournalEntryStatus::Failed`) park on disk indefinitely. The only way
entries are removed today is via successful replay (`lib.rs:1494,:1558`) or successful
parent-publish after mkdir (`write_ops.rs:679`).

**Lifecycle hooks available:**

- **Logout:** `commands/auth.rs:490-521` — `logout()` calls `unmount_filesystem()` then
  `clear_keys()`. The vault's `root_ipns_name` is available via
  `state.sdk.root_ipns_name.read().await` at this point. This is where vault-scoped purge
  must run.
- **Account switch:** No dedicated "account switch" command exists in the current
  `commands/` surface (verified via grep). Account switch likely flows through logout +
  login. The logout hook above catches it.
- **Account deletion:** No dedicated `delete_account` command found in the current
  `commands/` surface. If this is added in a future phase, it would need a purge hook.
  For Phase 52 scope: document and add a `WriteQueue::purge_vault(vault_root_ipns)` method
  so future phases can call it.

**Recommended GC constants (planner to confirm or adjust):**

- `JOURNAL_GC_MAX_AGE_DAYS: u64 = 30` — Failed entries older than 30 days are purged.
  Rationale: 30 days matches common cloud storage retry windows. Aligns with `JOURNAL_MAX_RETRIES = 5` (fuse/mod.rs:52): entries park as Failed after 5 retries; giving 30 days before purge gives ample time for human review.
- `JOURNAL_GC_MAX_SIZE_BYTES: u64 = 500 * 1024 * 1024` — 500 MB total Failed-entry budget (sum of all `.bin` sidecars + `.json` files for Failed entries). When exceeded, oldest-first purge runs.
- Both constants go in `crates/sdk/src/queue.rs` (or a new `constants.rs` in `crates/sdk`).

**Methods to add to WriteQueue:**

```rust
// Purge all entries (Pending, InProgress, Failed) for one vault.
pub fn purge_vault(&self, vault_root_ipns: &str) -> Result<usize, String>

// GC: purge Failed entries exceeding age_days or total_size_bytes budget.
pub fn gc_failed_entries(
    &self,
    age_days: u64,
    total_size_budget: u64,
) -> Result<usize, String>
```

`purge_vault` removes both `<id>.json` and `<id>.bin` for matching entries.
`gc_failed_entries` loads all entries, filters `JournalEntryStatus::Failed`, sorts by
`created_at_ms`, and purges oldest-first until under budget.

---

### D-03: Replay Timeout + Concurrent-with-Mount (WR-07)

**Current state:**

`apps/desktop/src-tauri/src/fuse/mod.rs:278-289` — `replay_for_vault` is awaited
**synchronously before** `CipherBoxFS` is constructed and before the FUSE thread is spawned.
A hung network call in replay blocks the entire mount.

`crates/fuse/src/lib.rs:1406-1588` — `replay_for_vault` is `async fn`. The inner replay
loops at lines 1447-1582 call `replay_mkdir_entry` and `replay_upload_entry` with raw `await`
and no `tokio::time::timeout` wrapper at the replay-entry level.

**NETWORK_TIMEOUT values in the codebase:**

Two definitions exist — they are NOT the same:
- `crates/fuse/src/lib.rs:59` — `const NETWORK_TIMEOUT: Duration = Duration::from_secs(10);`
  Used at lib.rs:69 (`block_with_timeout`) and lib.rs:1283 (FilePointer async resolution).
- `crates/fuse/src/operations.rs:37` — `pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(3);`
  Used at operations.rs:44 (`block_with_timeout` in the FS callback thread for sync ops).

The replay path lives in `lib.rs` and should use `lib.rs:59`'s 10-second timeout as its
per-network-call base. For large-file uploads (`upload_content` of a multi-GB sidecar),
a multiplier is appropriate.

**Existing `tokio::time::timeout` pattern to mirror:**

`crates/fuse/src/lib.rs:1283`:
```rust
let result = tokio::time::timeout(NETWORK_TIMEOUT, async {
    let resp = cipherbox_api_client::ipns::resolve_ipns(&api, &fp_ipns)
        .await
        .map_err(|e| format!("{}", e))?;
    ...
}).await;
```

**Recommended implementation for D-03:**

1. In `replay_for_vault`, wrap each `replay_mkdir_entry(...)` call:
   ```rust
   let result = tokio::time::timeout(
       NETWORK_TIMEOUT * 3,  // 30s for mkdir replay (metadata only, small)
       replay_mkdir_entry(...),
   ).await
   .unwrap_or_else(|_| Err(format!("replay_mkdir_entry timed out after {}s", NETWORK_TIMEOUT.as_secs() * 3)));
   ```

2. In `replay_for_vault`, wrap each `replay_upload_entry(...)` call:
   ```rust
   let result = tokio::time::timeout(
       NETWORK_TIMEOUT * 18, // 180s for upload replay (large file, 10s base × 18)
       replay_upload_entry(...),
   ).await
   .unwrap_or_else(|_| Err(format!("replay_upload_entry timed out after {}s", ...)));
   ```
   Rationale for 18×: a 2 GB file at typical IPFS upload speeds (~100 Mbps) takes ~160s.
   Rounding up to 180s gives headroom. The upload is already idempotent (same ciphertext →
   same CID), so a timeout retains the entry for the next mount.

3. Make replay concurrent with mount in `fuse/mod.rs`:
   ```rust
   // Before: replay_for_vault(...).await; then CipherBoxFS construction + mount
   // After:
   let replay_journal = journal.clone();
   let replay_api = state.sdk.api.clone();
   // ... clone other params ...
   tokio::spawn(async move {
       cipherbox_fuse::replay_for_vault(
           &replay_journal, replay_api, ...
       ).await;
   });
   // Immediately proceed to CipherBoxFS construction + mount
   ```
   The mount thread starts without waiting for replay. Replay entries that re-upload
   ciphertext and publish file metadata are idempotent; the FUSE filesystem handles
   concurrent live writes via the existing `write_generation` stale-drain guard.

**Windows mirror:** `apps/desktop/src-tauri/src/fuse/windows/mod.rs` also calls
`replay_for_vault` (CR-06 fix). The same concurrent-spawn pattern must be applied there.

---

### D-04: Name Encryption (IN-03) — Definitive Resolution

**Finding: ENCRYPT is required. OMIT is not viable.**

`crates/core/src/folder.rs:57` — `FilePointer.name: String` is the human-readable filename.
`crates/core/src/folder.rs:175-195` — `FileMetadata` has NO `name` field. It contains
only `cid`, `file_key_encrypted`, `file_iv`, `size`, `mime_type`, `encryption_mode`,
`created_at`, `modified_at`, `versions`.

`crates/fuse/src/lib.rs:2233` — `replay_upload_entry` constructs:
```rust
let file_pointer = FolderChild::File(FilePointer {
    id: format!("replay-{}", file_meta_ipns_name_str),
    name: filename.to_string(),   // <-- consumed from journal
    file_meta_ipns_name: file_meta_ipns_name_str.to_string(),
    ...
});
```
The `filename` field from the journal IS the `name` written into the parent folder's
decrypted metadata. Without it, the file appears in the directory with an empty name.

`crates/fuse/src/lib.rs:2030` — `replay_mkdir_entry` constructs:
```rust
let child_entry = FolderChild::Folder(FolderEntry {
    id: format!("replay-{}", child_ipns_name),
    name: name.to_string(),   // <-- consumed from journal
    ...
});
```
The `name` field from the journal IS the directory name in the parent folder metadata.

**Conclusion:** Both `filename` (UploadFile) and `name` (MkdirPublish) are required for
replay. They cannot be reconstructed from FileMetadata or from the parent folder's remote
metadata at replay time (the parent's remote metadata is the pre-crash state, which is
exactly what replay is patching). **The fallback applies: encrypt the names.**

**Encryption key available at both write and replay time:**

The user's EC public key (`self.public_key` / `public_key` parameter) is available at:
- Write time: `build_upload_journal_entry` at `journal_helpers.rs:111` receives `self` which has `self.public_key`
- Replay time: `replay_for_vault(... public_key: &[u8] ...)` at `lib.rs:1410`

The user's EC private key (`private_key`) is available at replay time and is already
used to ECIES-unwrap `parent_ipns_key_hex` and `file_ipns_key_hex`.

**Existing encryption helper to reuse:**

`cipherbox_crypto::ecies::wrap_key(plaintext: &[u8], public_key: &[u8])` — used throughout
the journal for key wrapping. Can wrap short strings (names are UTF-8 bytes).
`cipherbox_crypto::ecies::unwrap_key(ciphertext: &[u8], private_key: &[u8])` — used in
replay at lib.rs:2103-2104.

**Recommended implementation for D-04:**

In `JournalOp::UploadFile`, rename `filename: String` to `filename_encrypted_hex: String`.
In `build_upload_journal_entry`:
```rust
let filename_bytes = file_name.as_bytes();
let encrypted = cipherbox_crypto::ecies::wrap_key(filename_bytes, &self.public_key)
    .map_err(|e| format!("filename encryption failed: {}", e))?;
let filename_encrypted_hex = hex::encode(&encrypted);
```

In `replay_upload_entry`, add a `public_key` parameter (already present as `_public_key: &[u8]`,
currently unused — remove the underscore prefix):
```rust
let filename_bytes = cipherbox_crypto::ecies::unwrap_key(
    &hex::decode(filename_encrypted_hex)?,
    private_key,
)?;
let filename = String::from_utf8(filename_bytes)
    .map_err(|e| format!("filename UTF-8 decode: {}", e))?;
```

Same pattern for `MkdirPublish.name` → `name_encrypted_hex`.

**On-disk migration for existing entries:** Old entries with a plaintext `filename: String`
field in the JSON will fail to deserialize after the field is renamed. Add a
`#[serde(alias = "filename")]` on `filename_encrypted_hex` with an `Option<String>` compat
deserializer (matching the `deser_opt_string` pattern at `queue.rs:22-25`) that:
- If old `filename` field is present and value is not hex → treat as plaintext, log a
  migration warning, and pass through the plaintext for this replay only (one-time compat).
- If `filename_encrypted_hex` is present → hex-decode + ECIES-unwrap.

Alternatively: on the next mount, old-format entries will fail the compat check and be
parked as Failed with a clear error message, prompting the user to re-write those files.
The simpler, safer approach — document as a known limitation: pre-52 entries in the journal
are replayed with the old field via a `#[serde(alias)]`.

---

### D-05: sanitize_error Path Scrub (IN-04)

**Current state:**

`crates/sdk/src/sync.rs:265-285` — `regex_replace_paths`:
```rust
if c == '/' && (input[i..].starts_with("/Users/") || input[i..].starts_with("/home/")) {
    result.push_str("[path]");
    ...
}
```
Only two Unix path prefixes. Windows paths, `/var`, `/tmp`, `/private` leak through.

**Required additions:**

```rust
// Unix additions:
|| input[i..].starts_with("/var/")
|| input[i..].starts_with("/tmp/")
|| input[i..].starts_with("/private/")
// Windows drive-letter pattern (match 'C:\Users\', 'D:\Users\', etc.):
// Check: c.is_ascii_uppercase() && next chars are ":\Users\"
```

Windows path detection must be added as a separate branch since Windows paths start with
a drive letter, not `/`. The char_indices iterator approach already used makes this
straightforward: peek ahead two chars for `:\`.

**Existing test for sanitize_error:**

`crates/sdk/src/sync.rs` — check for existing unit tests:

```
grep -n "#\[test\]\|sanitize_error" crates/sdk/src/sync.rs
```

Tests exist at `crates/sdk/src/sync.rs` (confirmed log::info! / log::warn! usage at lines
83, 94, etc. — sync.rs has a `tests` module). The scrub extension needs a test for each
new prefix.

---

### D-06: Swallowed Removal Log (IN-05)

**Current three sites (confirmed by source read):**

1. `crates/fuse/src/lib.rs:1494` — inside the `Ok(())` arm of `replay_mkdir_entry` result:
   ```rust
   let _ = journal.remove(&entry.id);  // swallowed
   ```

2. `crates/fuse/src/lib.rs:1558` — inside the `Ok(())` arm of `replay_upload_entry` result:
   ```rust
   let _ = journal.remove(&entry.id);  // swallowed
   ```

3. `crates/fuse/src/write_ops.rs:679` — inside the `PublishResult::Success` arm after
   parent mkdir publish:
   ```rust
   let _ = journal_for_mkdir.remove(&mkdir_journal_entry_id);  // swallowed
   ```

**Logging facade in use:** `log` crate (confirmed: `crates/fuse/Cargo.toml:24:log = { workspace = true }`). Use `log::warn!`.

**Fix pattern for all three sites:**
```rust
if let Err(e) = journal.remove(&entry.id) {
    log::warn!(
        "replay_for_vault: failed to remove journal entry {} after success: {} (double-replay risk)",
        entry.id, e
    );
}
```

Note: `WriteQueue::remove` already returns `Ok(())` for NotFound (idempotent), so the
only error case is a genuine I/O error (permission denied, read-only filesystem). A
`log::warn!` is appropriate — the entry will be retried on next mount but the replay will
hit the `already_present` idempotency short-circuit and return `Ok(())` again.

---

## Don't Hand-Roll

| Problem                        | Don't Build                             | Use Instead                              | Why                                               |
| ------------------------------ | --------------------------------------- | ---------------------------------------- | ------------------------------------------------- |
| Name encryption at rest        | Custom cipher                           | `cipherbox_crypto::ecies::wrap_key`      | Same ECIES used for all key material in journal; unwrap already in replay path |
| Async timeout                  | Custom deadline/select! machinery       | `tokio::time::timeout`                   | Already used at lib.rs:1283; standard Tokio pattern |
| Concurrent replay              | Manual thread + JoinHandle              | `rt.spawn(async move {...})`             | Tokio runtime already present; spawn is the standard pattern |
| Oneshot reply for durable ack  | Custom atomic flag + spin loop          | `tokio::sync::oneshot`                   | Zero-overhead single-producer/consumer, drop-cancels on hang |
| Journal file streaming write   | Custom ring-buffer                      | `std::io::Write + file.sync_all()`       | Already used in WriteQueue::put; same pattern extended to sidecar |
| SHA-256 sidecar integrity      | Custom checksum                         | `sha2` crate (workspace, likely present) | Standard; verify before re-upload in replay |

---

## Common Pitfalls

### Pitfall 1: Reintroducing the False-Durability-Ack Bug (Phase-43 CR-04)

**What goes wrong:** The sidecar write moves off-thread, but the developer forgets to
block the FUSE callback thread on the oneshot reply before calling `reply.ok()`. The OS
receives a success ack before the journal entry is on disk.

**Why it happens:** The off-thread pattern looks like fire-and-forget; the durable-ack
requirement from Phase 43 is easy to miss.

**How to avoid:** The FUSE callback thread MUST `rt.block_on(oneshot_rx)` before the
`reply.ok()` call. Confirm in code review that the sequence is:
1. `rt.block_on(oneshot_rx)` → Ok
2. inode mutations
3. `reply.ok()`

**Warning signs:** The existing test `T-43-02` in 43-REVIEW.md and the crash-recovery test
at `queue.rs:827-851` (`crash_mid_write_entry_survives_reload`) will catch regression if
the new path bypasses fsync before ack.

### Pitfall 2: Sidecar Orphan on Failed JSON Write

**What goes wrong:** The background writer writes and fsyncs `<id>.bin` successfully, then
fails writing `<id>.json` (e.g., disk full). The `.bin` file is left on disk with no
corresponding `.json` entry. `load_all_for_vault` only reads `.json` files (confirmed at
`queue.rs:236`), so the orphaned `.bin` accumulates silently.

**How to avoid:** The GC (`gc_failed_entries`) must also scan for `.bin` files with no
matching `.json` and remove them. Alternatively, `put_with_sidecar` must remove the `.bin`
if the `.json` write fails (atomic cleanup).

### Pitfall 3: Double-Sidecar on Record_Failure Rewrite

**What goes wrong:** `record_failure` calls `update_status` → `put` which rewrites the
`.json` entry. If `put` for the retry/failure status update re-encodes `ciphertext_b64` in
the new schema but the sidecar already exists, the sidecar is written again unnecessarily.

**How to avoid:** `update_status`/`put` for status-only updates must not touch the sidecar.
The sidecar path is stored in the JSON; only the `.json` is rewritten on `update_status`.

### Pitfall 4: Replay Reads Sidecar Before Upload Thread Deletes It

**What goes wrong:** After a successful upload + parent-publish, the live upload thread
removes the `.json` entry (the current `already_present` idempotency short-circuit). If
replay runs concurrently, it may read the `.bin` sidecar while the upload thread is
uploading — benign since both produce the same CID — but if the upload thread removes
the `.bin` before replay reads it, replay fails with "sidecar not found."

**How to avoid:** Remove the `.bin` only AFTER the `.json` is removed (same parent-publish-
gated cleanup path as today). Replay's `already_present` check returns `Ok` without
touching the sidecar.

### Pitfall 5: Replay Concurrent with Mount — Race on `upload_tx`

**What goes wrong:** Replay spawned as a background tokio task tries to send
`FsEvent::UploadComplete` via `upload_tx` before `CipherBoxFS` is constructed and the
`upload_rx` end is wired up.

**How to avoid:** Replay does NOT send `FsEvent::UploadComplete`. Replay's responsibility
is to re-upload the ciphertext, re-publish file/folder IPNS metadata, and remove the
journal entry. The live upload path sends `UploadComplete`; replay does not. Confirm
`replay_upload_entry` at lib.rs:2055-2251 — it does not reference `upload_tx`. No race.

### Pitfall 6: D-04 Field Rename Breaks JSON Deserialization of Old Entries

**What goes wrong:** Renaming `filename: String` to `filename_encrypted_hex: String` causes
`serde_json::from_slice` to fail on pre-Phase-52 `.json` files. `load_all_for_vault` skips
them with a `log::warn!`, so they are silently abandoned on the first mount after upgrade.

**How to avoid:** Use `#[serde(alias = "filename")]` on the `filename_encrypted_hex` field
with a compat deserializer that detects whether the value is hex-encoded ECIES ciphertext
(length > some threshold) or a plaintext name (not hex-decodable). On compat deserialization
of a plaintext name, log a warning and use the plaintext directly for this replay pass —
then replay succeeds, the entry is removed, and the plaintext is never re-persisted.

---

## Code Examples

### Pattern 1: tokio::time::timeout for replay entries [ASSUMED based on existing lib.rs:1283 pattern]

```rust
// Source: crates/fuse/src/lib.rs:1283 (existing pattern, extended to replay)
let result = tokio::time::timeout(
    NETWORK_TIMEOUT * 18,  // 180s for large-file upload replay
    replay_upload_entry(&api, private_key, ...),
)
.await
.unwrap_or_else(|_| {
    Err(format!(
        "replay_upload_entry timed out after {}s",
        (NETWORK_TIMEOUT * 18).as_secs()
    ))
});
```

### Pattern 2: Concurrent replay via tokio::spawn in fuse/mod.rs [ASSUMED — mirrors existing spawn patterns]

```rust
// Source: pattern from rt.spawn at lib.rs:1282
let replay_journal = journal.clone();
let replay_api = state.sdk.api.clone();
let replay_private_key = private_key.clone();
// ... clone remaining params ...
rt.spawn(async move {
    cipherbox_fuse::replay_for_vault(
        &replay_journal,
        replay_api,
        &replay_private_key,
        ...
    )
    .await;
});
// Proceed immediately to CipherBoxFS construction and mount
```

### Pattern 3: ECIES name encryption using existing helpers [ASSUMED — same as wrap_key at journal_helpers.rs:150]

```rust
// Write side (journal_helpers.rs) — wrap filename bytes with user public key
let encrypted = cipherbox_crypto::ecies::wrap_key(file_name.as_bytes(), &self.public_key)
    .map_err(|e| format!("filename encryption failed: {}", e))?;
let filename_encrypted_hex = hex::encode(&encrypted);

// Replay side (lib.rs replay_upload_entry) — unwrap with user private key
let filename_bytes = cipherbox_crypto::ecies::unwrap_key(
    &hex::decode(filename_encrypted_hex)
        .map_err(|e| format!("hex decode filename: {}", e))?,
    private_key,
)
.map_err(|e| format!("ecies unwrap filename: {}", e))?;
let filename = String::from_utf8(filename_bytes)
    .map_err(|e| format!("filename UTF-8 decode: {}", e))?;
```

### Pattern 4: Swallowed removal fix (D-06) [ASSUMED — mirrors record_failure error handling at lib.rs:1564]

```rust
// Source: mirrors pattern at lib.rs:1564-1578
if let Err(e) = journal.remove(&entry.id) {
    log::warn!(
        "replay_for_vault: failed to remove journal entry {} after success: {} \
         — entry may replay again on next mount",
        entry.id, e
    );
}
```

### Pattern 5: regex_replace_paths extension (D-05) [ASSUMED — extends sync.rs:270-284]

```rust
// Source: crates/sdk/src/sync.rs:270-284 (existing, extended)
if c == '/'
    && (input[i..].starts_with("/Users/")
        || input[i..].starts_with("/home/")
        || input[i..].starts_with("/var/")
        || input[i..].starts_with("/tmp/")
        || input[i..].starts_with("/private/"))
{
    result.push_str("[path]");
    // skip until whitespace or quote
} else if c.is_ascii_uppercase()
    && input[i + 1..].starts_with(":\\Users\\")
{
    // Windows: C:\Users\...
    result.push_str("[path]");
    // skip until whitespace or quote
} else {
    result.push(c);
}
```

---

## State of the Art

| Old Approach                            | Current Approach (post-Phase-43/45/46)            | Phase 52 Change                                           |
| --------------------------------------- | ------------------------------------------------- | --------------------------------------------------------- |
| In-memory VecDeque (lost on quit)       | fsync-committed JSON journal with crash-replay    | Ciphertext in sidecar `.bin`; JSON holds path+hash only  |
| Full ciphertext in JSON (2.7 GB alloc)  | Still full ciphertext in JSON (WR-06 open)        | Sidecar: ciphertext streamed separately, never in JSON    |
| Replay blocks mount                     | Replay before mount (WR-07 open)                  | Replay concurrent with mount via tokio::spawn             |
| No network timeout in replay            | No timeout (WR-07 open)                           | tokio::time::timeout(NETWORK_TIMEOUT × k) per entry      |
| Plaintext filename in JSON at rest      | Plaintext filename in JSON (IN-03 open)           | ECIES-encrypted hex in JSON                               |
| /Users/ /home/ only in sanitize_error   | /Users/ /home/ only (IN-04 open)                  | + C:\Users\, /var, /tmp, /private                        |
| let _ = journal.remove() silently fails | let _ = journal.remove() silently fails (IN-05)   | log::warn! on removal errors                              |

---

## Assumptions Log

| #  | Claim                                                                                                | Section              | Risk if Wrong                                                            |
| -- | ---------------------------------------------------------------------------------------------------- | -------------------- | ------------------------------------------------------------------------ |
| A1 | MAX_JOURNAL_PAYLOAD cap of 2 GiB is the right balance                                               | D-01                 | Low: planner can adjust; the code pattern is the same regardless          |
| A2 | GC constants (30 days, 500 MB) are consistent with no-existing-cap baseline                          | D-02                 | Low: no conflicting desktop constants found; planner should confirm        |
| A3 | NETWORK_TIMEOUT multiplier of 3× (30s) for mkdir and 18× (180s) for upload are sensible             | D-03                 | Medium: depends on real-world upload speeds; plan should make these configurable |
| A4 | `sha2` is available in workspace for sidecar integrity hash                                          | D-01                 | Low: if absent, planner adds it; SHA-256 is standard                      |
| A5 | Account deletion requires a future WriteQueue::purge_vault call; no existing command to hook         | D-02                 | Low: no delete_account command found; purge_vault method is the right interface |
| A6 | Old-format compat deserialization via `#[serde(alias = "filename")]` is the right migration strategy | D-04                 | Low: alternative is silently park old entries; both are valid             |
| A7 | The `_public_key: &[u8]` parameter in replay_upload_entry (currently unused) is the right slot for name decryption | D-04  | Low: confirmed unused at lib.rs:2058; removing the underscore prefix is the correct fix |

---

## Open Questions

1. **D-01: oneshot vs. bounded channel for durable-ack**
   - What we know: `tokio::sync::oneshot` is the standard single-reply pattern.
   - What's unclear: should the FUSE callback thread have a timeout on the oneshot recv
     (e.g., 30s) so a wedged background writer doesn't block the FUSE thread forever?
   - Recommendation: Add a timeout on `rt.block_on(oneshot_rx)` matching the upload
     timeout window. If the background writer hasn't responded in 30s, reply EIO to the OS.

2. **D-02: Is there an account-switch command?**
   - What we know: `grep` found no `switch_account` or `delete_account` Tauri command.
   - What's unclear: account switch may be implemented as a frontend-driven logout + re-login
     flow that reuses the existing `logout()` hook.
   - Recommendation: Plan to add purge at the `logout()` site only; document that account
     deletion must add a `purge_vault` call when implemented.

3. **D-04: compat deserializer for old plaintext `filename` field**
   - What we know: the rename from `filename` to `filename_encrypted_hex` will break old
     entries on the first post-upgrade mount.
   - What's unclear: which strategy to use (passthrough plaintext once vs. park-and-fail).
   - Recommendation: Passthrough-once (log warn + use plaintext for one replay) is safer;
     park-and-fail is simpler but may silently lose in-flight writes.

---

## Environment Availability

Step 2.6: SKIPPED — all changes are Rust source edits in the existing workspace. No new
external tools, runtimes, databases, or services are required. `cargo test` and
`cargo check` are the only execution dependencies, and both are already in CI.

---

## Runtime State Inventory

Step 2.5: N/A — this is a hardening phase (no rename/refactor/migration of persisted keys).
The journal schema IS changing (ciphertext_b64 → sidecar_path; filename → filename_encrypted_hex),
but existing on-disk entries are handled via compat deserializers, not a data migration.
No OS-registered state, no external service config, no secrets/env vars affected.

---

## Validation Architecture

`nyquist_validation: true` (confirmed in .planning/config.json).

### Test Framework

| Property           | Value                                                    |
| ------------------ | -------------------------------------------------------- |
| Framework          | Rust built-in `#[test]` + `#[tokio::test]` (tokio dev-dep) |
| Config file        | Cargo.toml per crate — no separate test config           |
| Quick run command  | `cargo test -p cipherbox-sdk -p cipherbox-fuse`         |
| Full suite command | `cargo test --workspace --features fuse,winfsp`          |

Existing inline `#[cfg(test)] mod tests` blocks in `queue.rs` (lines 335-1078) and
`lib.rs` (lines 2276+) are the established test location. Tests are synchronous `#[test]`
for pure queue logic and `#[tokio::test]` for async replay logic.

### Phase Requirements → Test Map

| Req ID  | Behavior                                              | Test Type   | Automated Command                                                   | File Exists?    |
| ------- | ----------------------------------------------------- | ----------- | ------------------------------------------------------------------- | --------------- |
| HARD-03 | D-01: sidecar write does not include ciphertext in JSON | unit       | `cargo test -p cipherbox-sdk sidecar_ciphertext_not_in_json`        | No — Wave 0     |
| HARD-03 | D-01: release() acks only after sidecar fsync (durable-ack preserved) | unit | `cargo test -p cipherbox-sdk durable_ack_with_sidecar`        | No — Wave 0     |
| HARD-03 | D-01: per-entry size cap returns Err above threshold  | unit        | `cargo test -p cipherbox-fuse payload_size_cap_returns_err`         | No — Wave 0     |
| HARD-03 | D-02: purge_vault removes all entries for one vault   | unit        | `cargo test -p cipherbox-sdk purge_vault_removes_all`               | No — Wave 0     |
| HARD-03 | D-02: gc_failed_entries purges by age                 | unit        | `cargo test -p cipherbox-sdk gc_purges_old_failed`                  | No — Wave 0     |
| HARD-03 | D-02: gc_failed_entries purges to size budget         | unit        | `cargo test -p cipherbox-sdk gc_purges_to_size_budget`              | No — Wave 0     |
| HARD-03 | D-03: replay entry returns Err on timeout             | unit (async) | `cargo test -p cipherbox-fuse replay_entry_timeout`                | No — Wave 0     |
| HARD-03 | D-04: filename_encrypted_hex cannot be read as plaintext (JSON scrub) | unit | `cargo test -p cipherbox-sdk journal_no_plaintext_filename`    | No — Wave 0 (extends existing `journal_no_plaintext` test at queue.rs:434) |
| HARD-03 | D-04: round-trip: encrypt filename → write → reload → decrypt | unit | `cargo test -p cipherbox-sdk filename_encryption_round_trips`    | No — Wave 0     |
| HARD-03 | D-04: compat deserialization of old plaintext filename field | unit | `cargo test -p cipherbox-sdk legacy_plaintext_filename_compat`    | No — Wave 0     |
| HARD-03 | D-05: sanitize_error scrubs C:\Users\, /var, /tmp, /private | unit | `cargo test -p cipherbox-sdk sanitize_error_extended_paths`       | No — Wave 0     |
| HARD-03 | D-06: journal.remove failure logs warn! (not silently swallowed) | unit | `cargo test -p cipherbox-fuse remove_failure_is_logged`          | No — Wave 0     |

### Sampling Rate

- **Per task commit:** `cargo test -p cipherbox-sdk -p cipherbox-fuse 2>&1 | tail -20`
- **Per wave merge:** `cargo test --workspace --features fuse 2>&1 | tail -20`
- **Phase gate:** Full suite green (including `--features winfsp` via `cargo check`) before `/gsd-verify-work`

### Wave 0 Gaps

All test functions listed above are new. They extend existing inline `mod tests` blocks:
- `crates/sdk/src/queue.rs` — add new `#[test]` functions for D-01 sidecar, D-02 GC/purge, D-04 name encryption
- `crates/fuse/src/lib.rs` — add new `#[tokio::test]` functions for D-03 timeout, D-06 removal logging, D-01 durable-ack

No new test files needed; all tests live inline in the existing `#[cfg(test)] mod tests` blocks.

---

## Security Domain

`security_enforcement` not explicitly set to false in config.json → treat as enabled.

### Applicable ASVS Categories

| ASVS Category         | Applies | Standard Control                                                  |
| --------------------- | ------- | ----------------------------------------------------------------- |
| V2 Authentication     | no      | No auth changes in this phase                                     |
| V3 Session Management | partial | D-02 vault purge on logout/switch touches session lifecycle       |
| V4 Access Control     | no      | No access control changes                                         |
| V5 Input Validation   | yes     | D-05 sanitize_error: scrub-list extension is an output validation |
| V6 Cryptography       | yes     | D-04: ECIES name encryption — must use existing cipherbox_crypto::ecies::wrap_key, never hand-roll |
| V7 Error Handling     | yes     | D-06: removal errors must not be swallowed; D-03: timeout errors must surface to record_failure |

### Known Threat Patterns for This Stack

| Pattern                                       | STRIDE      | Standard Mitigation                                               |
| --------------------------------------------- | ----------- | ----------------------------------------------------------------- |
| Journal ciphertext on-disk (pre-D-01)         | Information Disclosure | D-01: ciphertext in 0600 sidecar, not in JSON             |
| Plaintext filename in 0600 journal (IN-03)    | Information Disclosure | D-04: ECIES-encrypt filename before persisting            |
| Path leak in tray/notification (IN-04)        | Information Disclosure | D-05: extend sanitize_error prefix list                   |
| Silent replay failure → double-publish (IN-05) | Tampering  | D-06: log::warn! on remove failure; idempotency is the guard    |
| Replay blocking mount → DoS                   | Denial of Service | D-03: concurrent replay + per-entry timeout                 |
| Cross-vault journal retention                 | Information Disclosure | D-02: purge_vault on logout/switch                        |

### Security Invariants That Must Not Regress

1. **Zero-knowledge at server:** No plaintext or unwrapped keys leave the device. D-04
   uses ECIES (user public key), so only the user can decrypt — server never sees names.
2. **Durable-ack contract:** OS must not be told a write succeeded unless the journal
   fsync is complete. D-01's off-thread pattern must preserve this (oneshot channel).
3. **0600 permissions:** Sidecar `.bin` files must be created with `0o600` (same as
   `.json` today at queue.rs:182). Use `OpenOptionsExt::mode(0o600)`.
4. **Sidecar removal:** `.bin` files must be removed together with `.json` files in all
   removal paths (successful replay, logout purge, GC) to avoid orphaned ciphertext on disk.

---

## Project Constraints (from CLAUDE.md)

- **Terminology:** Use `privateKey`, `publicKey`, `rootFolderKey`, `ipnsName`, `keyEpoch`,
  `encryptedIpnsPrivateKey` per the terminology standards table. In Rust, use snake_case
  equivalents: `private_key`, `public_key`, `root_folder_key`, `ipns_name`, `key_epoch`.
- **Security rules:** Never log sensitive keys. Never send unencrypted keys to server.
  Always use ECIES for key wrapping. The server NEVER has access to plaintext.
- **Rust/crypto:** Use `Uint8Array`/`Vec<u8>` for binary data; clear sensitive data from
  memory (`zeroize`). D-04 decrypted filename is transient — must NOT be stored back to disk.
- **TypeScript:** Not applicable to this phase (all Rust).
- **API generate:** Not applicable — no API endpoint changes.
- **No builds during planning:** Research was static analysis only. No `cargo build` run.
- **Git workflow:** Feature branch required. No direct push to main.
- **Conventional commits:** `feat(fuse): …` or `fix(fuse): …` format. No parens in subject line beyond scope parens.

---

## Sources

### Primary (HIGH confidence — direct codebase reads)

- `crates/sdk/src/queue.rs` — full source read; journal entry struct, ciphertext_b64 at :36, filename at :62, WriteQueue API, test patterns
- `crates/fuse/src/lib.rs` — partial reads: NETWORK_TIMEOUT at :59, replay_for_vault at :1406, swallowed removals at :1494/:1558, replay_upload_entry at :2055-2251, replay_mkdir_entry at :1918-2047
- `crates/fuse/src/journal_helpers.rs` — build_upload_journal_entry, filename capture at :224-228, ciphertext_b64 at :285-286, JournalOp construction at :307-321
- `crates/fuse/src/read_ops.rs` — handle_release at :800-970; durable-ack sequence at :814-884
- `crates/fuse/src/write_ops.rs` — swallowed removal at :679
- `crates/sdk/src/sync.rs` — sanitize_error at :244-263, regex_replace_paths at :265-285
- `crates/fuse/src/operations.rs` — NETWORK_TIMEOUT at :37, block_with_timeout at :39-49
- `crates/core/src/folder.rs` — FilePointer struct at :53-70, FileMetadata struct at :175
- `apps/desktop/src-tauri/src/fuse/mod.rs` — mount_filesystem, replay call at :278-289, JOURNAL_MAX_RETRIES at :52, default_journal_dir at :62-70
- `apps/desktop/src-tauri/src/commands/auth.rs` — logout hook at :490-521
- `.planning/phases/43-fuse-write-durability/43-REVIEW.md` — all criticals and warnings, CR-04 durable-ack fix, IN-03/04/05 descriptions
- `.planning/todos/pending/2026-06-18-fuse-journal-growth-and-replay-timeout.md` — re-verified findings post phases 45/46

### Secondary (MEDIUM confidence — context files)

- `.planning/phases/52-desktop-fuse-durability-at-rest-safety/52-CONTEXT.md` — locked decisions D-01..D-06
- `.planning/REQUIREMENTS.md` — HARD-03 definition

### Tertiary (LOW confidence — none)

No external web sources consulted. All findings are from codebase reads.

---

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — all libraries confirmed in Cargo.toml workspace
- Architecture: HIGH — all patterns traced to existing source with file:line citations
- Pitfalls: HIGH — derived from Phase-43 review findings and existing code analysis
- D-04 omit-vs-encrypt decision: HIGH — definitive: filename is used at lib.rs:2030 and lib.rs:2233

**Research date:** 2026-06-19
**Valid until:** 2026-07-19 (stable Rust codebase; 30-day window before re-verify)
