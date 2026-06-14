---
phase: 43-fuse-write-durability
reviewed: 2026-06-12T19:13:45Z
depth: standard
files_reviewed: 14
files_reviewed_list:
  - apps/desktop/src-tauri/src/fuse/mod.rs
  - apps/desktop/src-tauri/src/fuse/windows/mod.rs
  - apps/desktop/src-tauri/src/sync/mod.rs
  - apps/desktop/src-tauri/src/tray/mod.rs
  - apps/desktop/src-tauri/src/tray/status.rs
  - crates/fuse/Cargo.toml
  - crates/fuse/src/lib.rs
  - crates/fuse/src/platform/windows/write_ops.rs
  - crates/fuse/src/read_ops.rs
  - crates/fuse/src/write_ops.rs
  - crates/sdk/src/lib.rs
  - crates/sdk/src/queue.rs
  - crates/sdk/src/state.rs
  - crates/sdk/src/sync.rs
findings:
  critical: 8
  warning: 9
  info: 6
  total: 23
status: issues_found
---

# Phase 43: Code Review Report

**Reviewed:** 2026-06-12T19:13:45Z
**Depth:** standard
**Files Reviewed:** 14
**Status:** issues_found

## Summary

The journal primitive itself (`WriteQueue` in `crates/sdk/src/queue.rs`) is solid: fsync-before-return, 0600 perms, vault scoping, skip-on-malformed. The fsync-before-ack ordering in the happy path of both fuser and WinFsp callbacks is correct. However, the replay half of the feature is fundamentally broken, and several advertised behaviors are dead code:

1. Replay never publishes the parent IPNS record (no key in journal), yet returns `Ok`, removes the journal entry, and unpins the CID the parent IPNS record still points to. The original UAT orphan bug is NOT fixed by replay, and replay actively risks making existing folder metadata unfetchable.
2. Replay misinterprets the journaled ECIES-wrapped IPNS keys as raw 32-byte Ed25519 keys, so `UploadFile` replay with a key can never succeed, and `MkdirPublish` replay writes a TEE-wrapped key where a user-wrapped key belongs.
3. `record_failure`, parking, and `SyncStatus::WriteParked` have zero production callers — the retry/park/notify pipeline described in the phase goal does not exist end-to-end.
4. The WinFsp mirror does not compile (references to nonexistent types) and Windows never calls `replay_for_vault` at all.
5. The fuser release error path acks `reply.ok()` after a journal failure — the exact silent-loss the fsync-before-ack invariant exists to prevent.

## Critical Issues

### CR-01: Replay removes journal entries without any remote commit and unpins the live parent metadata CID

**File:** `crates/fuse/src/lib.rs:1080-1101` (callers: `lib.rs:926-933`, `lib.rs:964-973`)
**Issue:** `fetch_merge_publish_parent` uploads the merged metadata to IPFS but never publishes an IPNS record (the parent IPNS private key is not journaled — acknowledged in the inline comment). It then:

1. Returns `Ok(())`, so `replay_for_vault` calls `journal.remove(&entry.id)` — entry deleted with no confirmed remote commit. The journaled child is still absent from the parent folder listing. This is the exact orphan bug (UAT D-03) the phase claims to close; after one replay pass the journal is empty and the data is permanently orphaned.
2. Calls `unpin_content(api, &resolve.cid)` on the CID that the parent IPNS record STILL points to (line 1099). If GC collects it, the parent folder's current metadata becomes unfetchable — the whole subtree disappears. This is new data-loss risk introduced by this phase.
3. `coordinator.record_publish(parent_ipns_name, seq)` records a publish that never happened.

**Fix:** Journal must carry enough material to complete the parent publish (e.g., the user-ECIES-wrapped parent IPNS private key, unwrappable with `private_key` at replay time — same zero-knowledge posture as `FolderEntry.ipns_private_key_encrypted`). Until the publish succeeds (`PublishResult::Success`), `fetch_merge_publish_parent` must return `Err` so the caller keeps the entry. Delete the `unpin_content(&resolve.cid)` call entirely — never unpin a CID that an IPNS record still references.

### CR-02: UploadFile replay treats the ECIES-wrapped file IPNS key as a raw Ed25519 key — replay can never succeed

**File:** `crates/fuse/src/lib.rs:1195-1227` (journal write side: `crates/fuse/src/read_ops.rs:819-832`, `crates/fuse/src/platform/windows/write_ops.rs:882-895`)
**Issue:** The release path journals `file_ipns_key_hex` as the ECIES-wrapped key (`wrap_key(k, &fs.public_key)` → ~117+ bytes). `replay_upload_entry` hex-decodes it and does:

```rust
let ipns_key_arr: [u8; 32] = file_ipns_key.as_slice().try_into()
    .map_err(|_| "Invalid file IPNS key length for replay".to_string())?;
```

A wrapped key is never 32 bytes, so this always errors, the whole `replay_upload_entry` returns `Err`, the entry stays Pending, and is retried (and fails identically) on every subsequent mount, forever. Net effect: no `UploadFile` entry that carries a key is ever replayed or drained. Additionally, step 4 (line 1275-1282) re-wraps the already-wrapped bytes (`hex::decode(k)` then `wrap_key(&bytes, public_key)`), producing a double-wrapped `ipns_private_key_encrypted` that no client can ever decrypt — which would silently corrupt the file pointer if step 3 didn't fail first.

**Fix:** In `replay_upload_entry`, unwrap the journaled key with the user's private key before use:

```rust
let raw_key = cipherbox_crypto::ecies::unwrap_key(&hex::decode(k)?, private_key)?;
let ipns_key_arr: [u8; 32] = raw_key.as_slice().try_into()...;
```

And in step 4 store the journaled wrapped hex as-is (it is already user-wrapped) instead of re-wrapping.

### CR-03: MkdirPublish journals the TEE-wrapped IPNS key into a field replayed as the user-wrapped key

**File:** `crates/fuse/src/write_ops.rs:525`, `crates/fuse/src/platform/windows/write_ops.rs:153`, replay side `crates/fuse/src/lib.rs:1135`
**Issue:** `child_ipns_key_hex: encrypted_ipns_for_tee.clone().unwrap_or_default()` stores the IPNS private key wrapped with the **TEE public key** (or an empty string when `tee_public_key` is `None`). `replay_mkdir_entry` writes that value into `FolderEntry.ipns_private_key_encrypted`, which everywhere else in the codebase is the **user-ECIES-wrapped** key (`build_folder_metadata` at `lib.rs:619`, rmdir at `write_ops.rs:716`). After replay, the folder's IPNS private key in metadata is either TEE-wrapped (the client cannot unwrap it — folder becomes permanently unpublishable from any client) or empty. This breaks the metadata schema contract and quietly bricks write access to the replayed folder.

**Fix:** Journal the user-wrapped key (`wrap_key(&ipns_private_key, &fs.public_key)`) in `child_ipns_key_hex` — it is already computed for the parent metadata path. If the TEE-wrapped key is also needed for replaying the child's initial publish, store both as distinct fields with accurate names (`child_ipns_key_user_wrapped_hex`, `child_ipns_key_tee_wrapped_hex`).

### CR-04: fuser release acks `reply.ok()` when journal fsync (or any prepare step) fails — silent data loss

**File:** `crates/fuse/src/read_ops.rs:956-964`
**Issue:** When the prepare closure errors — including `fs.journal.put(&journal_entry)?` failing (disk full, journal dir deleted, permission error) and encryption failures — the `Err` arm logs, calls `handle.cleanup()` (deleting the plaintext temp file), then falls through to `reply.ok()` at line 964. The OS is told the close succeeded, no journal entry exists, no upload thread was spawned, and the plaintext temp file has been deleted. The write is gone with zero trace — precisely the failure mode the fsync-before-ack invariant (D-04) exists to prevent.

**Fix:**

```rust
Err(e) => {
    log::error!("File upload preparation failed for ino {}: {}", ino, e);
    handle.cleanup();
    reply.error(libc::EIO);
    return;
}
```

(With care to roll back the inode mutations made earlier in the closure — `inode.kind` reset and `pending_content` insert happen before `journal.put`, so a late failure currently also leaves local state claiming the write succeeded.)

### CR-05: Windows WinFsp upload path references nonexistent types — `winfsp` feature cannot compile

**File:** `crates/fuse/src/platform/windows/write_ops.rs:748-751`
**Issue:** The `UploadSpawnParams` struct added in this phase declares:

```rust
api: std::sync::Arc<cipherbox_api_client::ApiConfig>,
rt: std::sync::Arc<tokio::runtime::Runtime>,
coordinator: std::sync::Arc<crate::publish_coordinator::PublishCoordinator>,
```

- `cipherbox_api_client::ApiConfig` does not exist (the client type is `ApiClient`, `crates/api-client/src/client.rs:17`); `fs.api.clone()` is `Arc<ApiClient>`.
- `CipherBoxFS.rt` is `tokio::runtime::Handle`, not `Arc<Runtime>`.
- There is no `publish_coordinator` module in the fuse crate; `PublishCoordinator` lives at crate root.

This code is gated behind `#[cfg(feature = "winfsp")]`, which is not part of `default` features, so the macOS/Linux build being "clean" proves nothing about it. The Windows mirror of the durability fix is unverified, non-compiling code.

**Fix:** Match the fuser struct (`Arc<ApiClient>`, `tokio::runtime::Handle`, `Arc<crate::PublishCoordinator>`) and add a CI check that compiles `--features winfsp` (e.g., `cargo check --no-default-features --features winfsp` on a Windows runner or with a stubbed winfsp dep).

### CR-06: Windows mount never calls `replay_for_vault` — journal is write-only on Windows

**File:** `apps/desktop/src-tauri/src/fuse/windows/mod.rs:66-72, 332-365`
**Issue:** The macOS mount path calls `cipherbox_fuse::replay_for_vault(...)` before mounting (`apps/desktop/src-tauri/src/fuse/mod.rs:233-242`). The Windows mount constructs the same journal and passes it into `CipherBoxFS`, but never replays. On Windows, journaled entries accumulate forever and crashed writes are never recovered — the headline durability guarantee of this phase ("replay on mount") does not exist on Windows. (The Windows coordinator is also not seeded with initial sequences, unlike macOS.)

**Fix:** Call `replay_for_vault` after the pre-populate block and before constructing `CipherBoxFS`, mirroring `fuse/mod.rs:233-242`.

### CR-07: Retry/park/notify pipeline is dead code — `record_failure` and `SyncStatus::WriteParked` have zero production callers

**File:** `crates/sdk/src/queue.rs:245-265`, `crates/sdk/src/state.rs:24-29`, `crates/sdk/src/sync.rs:97-136`, `apps/desktop/src-tauri/src/sync/mod.rs:39-51`
**Issue:** Grep confirms `record_failure` is called only from unit tests, and `SyncStatus::WriteParked` is constructed only in tests. The sync daemon emits only `Idle`/`Syncing`/`Error`. Consequences:

- `retries` never increments; no entry ever transitions to `Failed`; `max_retries` (injected as 5) is inert.
- The tray `WriteParked` state and `send_write_parked_notification` are unreachable.
- A background upload failure during a live session is only an error log (`read_ops.rs:948-952`); the entry is never retried until the next mount, and the user is never informed. The phase's stated deliverable — "max-retry exhaustion parks the entry as Failed and surfaces `SyncStatus::WriteParked` → tray + OS notification" — is not implemented anywhere.

Additionally, `SyncDaemon` constructs `WriteQueue::default()` (`sync.rs:64`) pointing at `temp_dir/cipherbox-journal-default`, a directory that is never created and is unrelated to the real `cb-journal` dir — the daemon cannot even see the real journal.

**Fix:** Inject the real journal (dir) into `SyncDaemon`; in `sync_cycle`, load pending/failed counts via `load_all_for_vault` and emit `WriteParked` accordingly; have the background-upload failure paths (`read_ops.rs:948`, windows `write_ops.rs:1002`) call `record_failure` on the persisted entry.

### CR-08: Journal entry removed after ciphertext upload but before the parent folder pointer is committed

**File:** `crates/fuse/src/read_ops.rs:941-943` (Windows: `crates/fuse/src/platform/windows/write_ops.rs:996-997`)
**Issue:** The release upload thread removes the journal entry once `upload_content` (and a best-effort `publish_file_metadata`) finish. But the parent folder pointer publish — the thing that makes the file visible — happens later via the debounced publisher (`queue_publish` → `flush_publish_queue`, 1.5s+ debounce), is not journaled, and uses live inode state. A crash or quit in that window leaves a pinned, IPNS-published file that no folder metadata references, with an empty journal: unrecoverable orphan. Also note the entry is removed even when `publish_file_metadata` **failed** (only `log::warn!` at `read_ops.rs:933`), so "removal only after confirmed remote commit" is violated on two counts.

**Fix:** Remove the entry only after the parent folder publish for this file is confirmed (e.g., signal back through `UploadComplete`/the debounced publisher, removing the entry when the parent publish containing this `file_meta_ipns_name` succeeds), and only when `publish_file_metadata` succeeded.

## Warnings

### WR-01: Replay order is nondeterministic — `created_at_ms` is never used

**File:** `crates/sdk/src/queue.rs:272-285`, `crates/sdk/src/queue.rs:171-222`
**Issue:** `load_all_for_vault` returns entries in `read_dir` order, which is filesystem-arbitrary (not insertion order). `ordered_for_replay` only partitions Mkdir-before-Upload and "preserves relative order" of an already-arbitrary input. Nested offline mkdirs (`a/` then `a/b/`) can replay child-before-parent; two writes to the same file can replay newest-then-oldest, resurrecting stale content as the final state.
**Fix:** Sort each group by `created_at_ms` (already serialized in every op) before replay.

### WR-02: `resolve_folder_key` only searches the root's direct children — replay fails for anything nested deeper than one level

**File:** `crates/fuse/src/lib.rs:1006-1018`
**Issue:** Only `root_meta.children` is scanned for the parent folder's wrapped key. Any journaled write whose parent is two or more levels deep returns "folder IPNS not found in root metadata" on every mount, forever (no retry cap per CR-07). The mounted FS supports arbitrary nesting, so this is a common case, not an edge.
**Fix:** Recursive/BFS traversal of folder metadata (resolving each subfolder's key as you descend), or journal the parent's wrapped folder key alongside the entry.

### WR-03: Journal file permission race and missing parent-directory fsync

**File:** `crates/sdk/src/queue.rs:126-150`
**Issue:** (a) The file is created with default (umask-derived) permissions and only chmod'd to 0600 after the ciphertext and wrapped keys are fully written and fsynced — a window where other local users may read it on permissive umasks. (b) `sync_all` on the file does not persist the new directory entry; on ext4/APFS a crash immediately after `put()` can lose the file itself, so the "durable before ack" guarantee is weaker than claimed.
**Fix:** (a) `OpenOptions::new().mode(0o600)` (via `std::os::unix::fs::OpenOptionsExt`) at create time. (b) Open and `sync_all()` the journal directory after creating the file.

### WR-04: mkdir leaves a ghost inode in the local table when a late prepare step fails

**File:** `crates/fuse/src/write_ops.rs:482-534` (Windows: `platform/windows/write_ops.rs:116-162`)
**Issue:** The new folder inode is inserted into `fs.inodes` and the parent's children before `build_folder_metadata` and the newly added `fs.journal.put(...)?`. If either fails, the kernel gets EIO but the local table keeps the directory; subsequent readdir shows a folder the OS believes was never created, and the debounced publisher can publish the phantom entry to remote metadata. `journal.put` adds a new failure point after the insertion.
**Fix:** On the `Err` path, remove the inode and the parent-children entry (mirroring `handle_create`'s rollback at `write_ops.rs:230-241`), or perform journal.put before inserting the inode.

### WR-05: mkdir-conflict retry path never removes the journal entry after the re-armed publish succeeds

**File:** `crates/fuse/src/write_ops.rs:631-641`, `crates/fuse/src/lib.rs:686-692`
**Issue:** On parent-publish conflict the journal entry is deliberately retained and `FsEvent::MkdirConflict` re-arms the debounced publisher — but the debounced path (`flush_publish_queue` → `spawn_metadata_publish`) has no knowledge of the journal entry and never removes it on success. The entry stays Pending for the rest of the session and is replayed on the next mount; the only cleanup is replay's `already_present` idempotency short-circuit, which never runs on Windows (CR-06) and sits inside the broken replay path (CR-01).
**Fix:** Thread the journal entry id through the conflict event so the successful debounced publish removes it, or have replay's idempotency check be the documented and tested cleanup mechanism once CR-01/CR-06 are fixed.

### WR-06: Unbounded journal growth and full-ciphertext-in-JSON design

**File:** `crates/sdk/src/queue.rs:120-153`, `crates/fuse/src/read_ops.rs:808-844`
**Issue:** Each `UploadFile` entry embeds the entire file ciphertext as base64 inside a JSON document: a 2 GB file becomes a ~2.7 GB allocation in `serde_json::to_vec`, then a multi-GB write + F_FULLFSYNC executed on the single FUSE callback thread (macOS) or while holding the global WinFsp mutex (Windows) — blocking the whole filesystem for the duration, and capable of aborting on memory. There is no size cap, no GC of parked `Failed` entries, and entries from other vaults persist forever after account switch (the `cb-journal` dir is shared and only ever filtered, never pruned).
**Fix:** Store ciphertext in a sidecar file (`<id>.bin`) streamed to disk with the JSON holding only its path/hash; cap journaled payload size or fall back to a temp-ciphertext-file reference; add GC for parked entries (age/size budget) and an explicit purge on logout/account deletion.

### WR-07: `replay_for_vault` runs inline in mount with no network timeouts

**File:** `apps/desktop/src-tauri/src/fuse/mod.rs:233-242`, `crates/fuse/src/lib.rs:870-977`
**Issue:** Replay awaits raw `resolve_ipns`/`fetch_content`/`upload_content` calls per entry (several round trips each) with none of the `NETWORK_TIMEOUT` discipline used elsewhere in the crate (`block_with_timeout`, `lib.rs:54-69`). A hung connection during replay stalls `mount_filesystem` indefinitely; many entries on a slow link delay mount by minutes.
**Fix:** Wrap each entry's replay in `tokio::time::timeout(NETWORK_TIMEOUT * k, ...)`, and/or run replay concurrently with (not before) mount.

### WR-08: Empty `file_meta_ipns_name` is journaled and replayed into parent metadata

**File:** `crates/fuse/src/read_ops.rs:803-805` (Windows: `write_ops.rs:866-868`), replay `crates/fuse/src/lib.rs:1271-1294`
**Issue:** `file_meta_ipns_name.clone().unwrap_or_default()` journals an empty string when the inode lacks a file IPNS name. Replay then merges a `FilePointer` with `file_meta_ipns_name: ""` into the remote parent metadata — an invalid child that downstream consumers skip with errors (`build_folder_metadata` logs "has no fileMetaIpnsName") and that the `already_present` check matches against any other empty-keyed entry.
**Fix:** Refuse to journal (or refuse to replay) `UploadFile` entries with an empty `file_meta_ipns_name`; treat it as a prepare error.

### WR-09: `WriteQueue::Default` points at a nonexistent temp directory

**File:** `crates/sdk/src/queue.rs:288-292`, `crates/sdk/src/sync.rs:64`
**Issue:** `Default` resolves to `temp_dir()/cipherbox-journal-default`, which is never created (the constructor documents "directory must already exist"), so any `put` through it fails; and temp dirs are wiped on reboot, contradicting the durability purpose. Its only consumer is the dead `SyncDaemon.write_queue` field (see CR-07).
**Fix:** Remove the `Default` impl and the daemon's `write_queue`/`write_queue_mut` until the daemon is wired to the real journal.

## Info

### IN-01: Off-by-one in retry accounting

**File:** `crates/sdk/src/queue.rs:250`
**Issue:** Parking happens when `retries >= max_retries` after the increment path, so `max_retries = 5` yields 6 attempts. Harmless but the name lies.
**Fix:** Park when `entry.retries + 1 >= max_retries`, or document the semantics.

### IN-02: One bad directory entry aborts the whole journal load

**File:** `crates/sdk/src/queue.rs:180-182`
**Issue:** `dir_entry.map_err(...)?` fails the entire `load_all_for_vault` on a single transient `read_dir` entry error, unlike the skip-with-warn handling of unreadable/malformed files just below.
**Fix:** `continue` with a `log::warn!` instead of `?`.

### IN-03: Plaintext file and directory names persisted in journal JSON

**File:** `crates/sdk/src/queue.rs:33-34, 50-51`
**Issue:** `filename` / `name` are stored in cleartext on disk (0600, local-only). Content and keys are protected, but this is a new at-rest disclosure of vault item names not previously persisted anywhere locally. Worth a threat-model note; not a zero-knowledge violation toward the server.
**Fix:** Acceptable as-is if documented; alternatively encrypt names with the user public key like other metadata.

### IN-04: `sanitize_error` path scrubbing misses Windows and other Unix paths

**File:** `crates/sdk/src/sync.rs:226-245`
**Issue:** Only `/Users/` and `/home/` prefixes are scrubbed; `C:\Users\...`, `/var/`, `/tmp/`, `/private/` leak through into tray/notification copy.
**Fix:** Extend the prefix list and add a drive-letter pattern.

### IN-05: Journal removal errors silently swallowed

**File:** `crates/fuse/src/read_ops.rs:943`, `crates/fuse/src/write_ops.rs:628`, `crates/fuse/src/lib.rs:929, 968`
**Issue:** `let _ = journal.remove(...)` everywhere. A failed removal means the entry replays later; combined with the idempotency gaps above this can double-publish. At minimum log the error.
**Fix:** `if let Err(e) = journal.remove(...) { log::warn!(...) }`.

### IN-06: `record_publish` called for a publish that never happened

**File:** `crates/fuse/src/lib.rs:1097`
**Issue:** `fetch_merge_publish_parent` seeds the sequence cache via `record_publish(parent_ipns_name, seq)` despite publishing nothing. Currently masked by CR-01; remove when reworking that function so the cache only reflects confirmed publishes.
**Fix:** Delete the call; `resolve_sequence` already updated the cache with the resolved value.

## Post-Review Resolution (2026-06-14)

All 8 critical findings (CR-01..CR-08) were verified resolved via a code cross-check against the current implementation and a CodeRabbit re-review on 2026-06-14.

| Finding | Status | Resolution (commits) |
| ------- | ------ | -------------------- |
| CR-01 | FIXED | Replay now journals the user-ECIES-wrapped parent IPNS key, CAS-publishes the parent IPNS record, returns `Err` until `PublishResult::Success` (entry retained on failure), and unpins only in the post-Success arm against the stale pre-merge CID (4bc1a0278, 0b8545bad, 7633cf795). |
| CR-02 | FIXED | `replay_upload_entry` now unwraps the journaled key with the user private key before the `[u8;32]` conversion, and step 4 stores the journaled wrapped hex as-is with no double-wrap (4bc1a0278, 0b8545bad). |
| CR-03 | FIXED | Both fuser and winfsp paths journal the user-ECIES-wrapped child IPNS key; the TEE-wrapped key is segregated to the live publish request, the residual TEE fallback was removed, and journal IPNS-key wraps now warn-and-empty on failure (this change). |
| CR-04 | FIXED | The fuser prepare-failure path returns `reply.error(EIO)` instead of `reply.ok()`, and all in-memory mutations (inode kind/attr, pending_content, queued publish) are deferred until after the journal fsync, so a failure leaves no partial state and needs no rollback; Windows Cleanup returns VOID, so the same no-mutation-on-failure deferral is its mitigation (4e8c48020, this change). |
| CR-05 | FIXED | `UploadSpawnParams` now uses `Arc<ApiClient>`, `tokio::runtime::Handle`, and `Arc<crate::PublishCoordinator>`; CI compiles `cargo check --features winfsp` (963468eed). |
| CR-06 | FIXED | Windows mount now calls `replay_for_vault` and seeds the coordinator, mirroring macOS (ad2339d7e). |
| CR-07 | FIXED | `SyncDaemon` is wired to the real cb-journal `WriteQueue` (Default impl removed); `sync_cycle` loads entries via `load_all_for_vault` and emits `SyncStatus::WriteParked`, background-upload failures call `record_failure`, and the tray surfaces WriteParked plus a notification (d5cae52fc, 0d4cc08c4, 7633cf795, 7a9f3ca75, 5b6455c34). |
| CR-08 | FIXED | Entry removal is now replay-only and parent-publish-gated; the live upload thread no longer removes entries and `publish_file_metadata` failure no longer triggers removal (4e8c48020, 293de3f4c). |

---

Reviewed: 2026-06-12T19:13:45Z
Reviewer: Claude (gsd-code-reviewer)
Depth: standard
