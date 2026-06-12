---
phase: 43-fuse-write-durability
verified: 2026-06-12T20:30:00Z
status: gaps_found
score: 9/18 must-haves verified
overrides_applied: 0
gaps:
  - truth: "D-04 (fuser release error path): handle_release acks reply.ok() when journal.put fails — silent data loss on journal failure"
    status: failed
    reason: "read_ops.rs:956-964: Err arm calls handle.cleanup() then falls through to reply.ok() at line 964, acking the OS after a journal fsync failure with no entry on disk and no upload thread spawned"
    artifacts:
      - path: "crates/fuse/src/read_ops.rs"
        issue: "Lines 956-964: prepare_result Err path calls handle.cleanup() and falls through to reply.ok(); must call reply.error(libc::EIO) instead"
    missing:
      - "Change the Err arm of prepare_result to: log::error!(...); handle.cleanup(); reply.error(libc::EIO); return;"

  - truth: "D-06: replay fetches parent folder's CURRENT remote metadata, merges, and CAS-publishes — never re-publishes the stale snapshot; and fetch_merge_publish_parent must not unpin the live CID before IPNS is updated"
    status: failed
    reason: "fetch_merge_publish_parent (lib.rs:1082-1101) uploads merged metadata to IPFS but never publishes an IPNS record (parent IPNS private key not journaled). It then (1) returns Ok() so replay removes the journal entry with no confirmed remote commit — the orphan bug is NOT closed; (2) calls unpin_content(api, &resolve.cid) at line 1099, unpinning the CID the parent IPNS record STILL points to, which can make the current parent folder metadata unfetchable if GC collects it — new data-loss risk introduced by this phase; (3) calls coordinator.record_publish() for a publish that never happened"
    artifacts:
      - path: "crates/fuse/src/lib.rs"
        issue: "Lines 1081-1101: fetch_merge_publish_parent skips IPNS publish, still returns Ok, removes journal entry, and unpins live CID. journal.remove() at lines 929, 968 called after this non-publishing Ok return."
    missing:
      - "Journal must carry the user-ECIES-wrapped parent IPNS private key so replay can sign and publish the IPNS record"
      - "fetch_merge_publish_parent must return Err (not Ok) when parent IPNS private key is unavailable, so the journal entry is retained"
      - "Delete the unpin_content(&resolve.cid) call — never unpin a CID that an active IPNS record still references"
      - "Remove the coordinator.record_publish() call for unpublished records"

  - truth: "D-06 (CR-02): UploadFile replay treats the ECIES-wrapped file IPNS key as a raw 32-byte Ed25519 key — replay always errors"
    status: failed
    reason: "lib.rs:1197-1199 hex-decodes the ECIES-wrapped key (117+ bytes) then line 1224-1227 does try_into::<[u8;32]>() which always fails, causing every UploadFile entry with a key to return Err permanently and never replay. Additionally lib.rs:1275-1282 re-wraps already-wrapped bytes producing a doubly-wrapped key in the stored FilePointer."
    artifacts:
      - path: "crates/fuse/src/lib.rs"
        issue: "Lines 1197-1227: ECIES-wrapped key (117 bytes) cannot be cast to [u8;32]; must unwrap with ecies::unwrap_key(bytes, private_key) first. Lines 1275-1282: re-wraps an already-wrapped key; must store the journaled hex as-is (already user-wrapped)."
    missing:
      - "In replay_upload_entry: let raw_key = cipherbox_crypto::ecies::unwrap_key(&hex::decode(file_ipns_key_hex)?, private_key)?; then cast raw_key to [u8;32]"
      - "In step 4: store the journaled file_ipns_key_hex directly as ipns_private_key_encrypted without re-wrapping"

  - truth: "D-03 (CR-03): MkdirPublish journals the TEE-wrapped IPNS key; replay writes it as user-wrapped — metadata schema contract broken"
    status: failed
    reason: "write_ops.rs:525 and windows/write_ops.rs:153 set child_ipns_key_hex = encrypted_ipns_for_tee (TEE-wrapped or empty). replay_mkdir_entry (lib.rs:1135) writes this into FolderEntry.ipns_private_key_encrypted which everywhere else is the user-ECIES-wrapped key. After replay the folder's IPNS key is either TEE-wrapped (client cannot unwrap) or empty — the folder becomes permanently unpublishable from any client."
    artifacts:
      - path: "crates/fuse/src/write_ops.rs"
        issue: "Line 525: child_ipns_key_hex should be the user-ECIES-wrapped IPNS private key, not encrypted_ipns_for_tee"
      - path: "crates/fuse/src/platform/windows/write_ops.rs"
        issue: "Line 153: same issue — TEE-wrapped key journaled instead of user-wrapped key"
      - path: "crates/fuse/src/lib.rs"
        issue: "Line 1135: replay_mkdir_entry writes child_ipns_key_hex into FolderEntry.ipns_private_key_encrypted"
    missing:
      - "Journal the user-ECIES-wrapped IPNS key (wrap_key(&ipns_private_key, &fs.public_key)) as child_ipns_key_hex in MkdirPublish entries"
      - "If the TEE-wrapped key is also needed for child IPNS replay, add a separate field (e.g. child_ipns_key_tee_wrapped_hex) distinct from the user-wrapped field"

  - truth: "D-12 (CR-05): Windows WinFsp upload path uses nonexistent types in UploadSpawnParams — winfsp feature does not compile"
    status: failed
    reason: "windows/write_ops.rs:748-751: UploadSpawnParams declares api: Arc<cipherbox_api_client::ApiConfig> (type does not exist; should be Arc<ApiClient>), rt: Arc<tokio::runtime::Runtime> (wrong; CipherBoxFS.rt is tokio::runtime::Handle), coordinator: Arc<crate::publish_coordinator::PublishCoordinator> (module does not exist; PublishCoordinator is at crate root). The winfsp feature is gated and does not compile on the current codebase."
    artifacts:
      - path: "crates/fuse/src/platform/windows/write_ops.rs"
        issue: "Lines 748-751: wrong types in UploadSpawnParams struct — ApiConfig should be ApiClient, Arc<Runtime> should be Handle, crate::publish_coordinator::PublishCoordinator should be crate::PublishCoordinator"
    missing:
      - "Fix UploadSpawnParams field types to match CipherBoxFS: api: Arc<cipherbox_api_client::ApiClient>, rt: tokio::runtime::Handle, coordinator: Arc<crate::PublishCoordinator>"

  - truth: "D-12 (CR-06): Windows mount never calls replay_for_vault — journal is write-only on Windows, replay guarantee absent"
    status: failed
    reason: "apps/desktop/src-tauri/src/fuse/windows/mod.rs constructs the journal and passes it to CipherBoxFS (lines 65-72, 361) but never calls cipherbox_fuse::replay_for_vault. On Windows, journaled entries accumulate forever and crashed writes are never recovered."
    artifacts:
      - path: "apps/desktop/src-tauri/src/fuse/windows/mod.rs"
        issue: "No call to cipherbox_fuse::replay_for_vault after the pre-populate block; journal is injected but replay is absent"
    missing:
      - "Call cipherbox_fuse::replay_for_vault(&journal, api, private_key, public_key, root_folder_key, &root_ipns_name, coordinator) before constructing CipherBoxFS, mirroring fuse/mod.rs:233-242"

  - truth: "D-09/D-10 (CR-07): record_failure and SyncStatus::WriteParked have zero production callers — retry/park/notify pipeline is dead code"
    status: failed
    reason: "grep confirms record_failure is called only from unit tests. SyncStatus::WriteParked is constructed only in tests. SyncDaemon (sync.rs:64) uses WriteQueue::default() pointing at temp_dir/cipherbox-journal-default (never created, wiped on reboot). The background upload failure path (read_ops.rs:948-952, windows/write_ops.rs:1003) only logs errors — never calls record_failure. The phase-stated deliverable of retry/park/notification pipeline does not exist end-to-end."
    artifacts:
      - path: "crates/sdk/src/sync.rs"
        issue: "Line 64: WriteQueue::default() used — points at a temp dir that is never created and is wiped on reboot; unrelated to the real cb-journal dir"
      - path: "crates/fuse/src/read_ops.rs"
        issue: "Lines 948-952: upload failure only logs error, never calls journal.record_failure"
      - path: "crates/fuse/src/platform/windows/write_ops.rs"
        issue: "Lines 1003+: upload failure only logs, never calls record_failure"
    missing:
      - "Inject the real journal into SyncDaemon; load pending/failed counts via load_all_for_vault in sync_cycle and emit WriteParked"
      - "Call journal.record_failure on background upload failure in read_ops.rs handle_release thread error path"
      - "Call journal.record_failure on background upload failure in Windows handle_cleanup thread error path"
      - "Remove WriteQueue::default() or fix it to point at the real cb-journal dir"

  - truth: "D-08/CR-08: journal entry is removed after ciphertext upload but before the parent folder pointer is published — still an irrecoverable orphan window"
    status: failed
    reason: "read_ops.rs:941-943 and windows/write_ops.rs:996-997 remove the journal entry once upload_content succeeds and the background UploadComplete is sent. But the parent folder pointer publish happens via the debounced publisher (1.5s+) which has no journal knowledge. A crash/quit between upload_content success and debounced publish leaves a pinned IPNS-published file with an empty journal and no folder metadata reference. Also: the entry is removed even when publish_file_metadata fails (only log::warn at read_ops.rs:933)."
    artifacts:
      - path: "crates/fuse/src/read_ops.rs"
        issue: "Lines 941-943: journal.remove called after upload_content succeeds, before parent folder pointer is published via debounced publisher"
      - path: "crates/fuse/src/platform/windows/write_ops.rs"
        issue: "Lines 996-997: same premature removal"
    missing:
      - "Journal entry should only be removed after the parent folder metadata is published (either thread the entry id through UploadComplete and remove in the debounced publish path, or document and test the recovery flow explicitly)"
      - "Entry must not be removed when publish_file_metadata failed (guard the remove with the publish success check)"

human_verification:
  - test: "Journal survival after SIGKILL"
    expected: "Copy a file into ~/CipherBox, SIGKILL desktop before upload completes, relaunch and remount. File should be replayed on mount and present remotely. The cb-journal entry should disappear after successful replay."
    why_human: "Cannot test crash-and-replay headlessly; requires running desktop app, actual filesystem mount, and kill/restart cycle"
  - test: "Park notification render"
    expected: "Force upload failure (stop API), copy a file, exhaust retries. OS notification titled 'CipherBox Upload Failed' appears. Tray shows 'Upload Failed'. Journal entry remains on disk with Failed status."
    why_human: "Cannot test OS notification rendering headlessly; requires live app and controlled network failure. Also blocked by CR-07 (record_failure has no production callers) — this test will NOT pass until CR-07 is fixed."
  - test: "Mkdir orphan survival"
    expected: "mkdir with parent-publish conflict; folder survives restart, parent publishes correctly, no orphan"
    why_human: "Requires inducing a parent-publish conflict in a live session; cannot be done headlessly"
  - test: "Ciphertext-only journal check"
    expected: "Open any cb-journal/*.json file; contains only base64/hex ciphertext, wrapped keys, IVs, IPNS names — never readable file content"
    why_human: "Requires creating a journal entry with a known file in a live session"
---

# Phase 43: FUSE Write Durability Verification Report

**Phase Goal:** Make FUSE writes durable: persisted out-of-callback pending-upload journal so `release()` no longer falsely acks then silently loses data, and mkdir parent-publish conflicts actually enqueue a retry instead of orphaning the child folder.
**Verified:** 2026-06-12T20:30:00Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

The phase establishes a correct journal primitive and correctly wires the fsync-before-ack ordering in the fuser and WinFsp happy paths. However, the replay half of the phase — which is what closes the original UAT bug — is fundamentally broken in several interlocking ways. The phase goal states "mkdir parent-publish conflicts actually enqueue a retry instead of orphaning the child folder" but replay cannot complete a parent IPNS publish (no key in journal), actively unpins the live parent CID in the process, and still removes the journal entry, leaving the data in a worse state than before. The phase also does not wire the retry/park/notification pipeline end-to-end (record_failure has zero production callers).

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|---------|
| 1 | D-01: WriteQueue is persist-backed in crates/sdk/src/queue.rs | VERIFIED | queue.rs exists with PathBuf journal_dir, put/remove/load_all_for_vault, sync_all() barrier |
| 2 | D-02: Journal entries carry stable identifiers, NO ino/parent_ino | VERIFIED | queue.rs:JournalOp fields use IPNS names; grep for "parent_ino" or "ino:" in struct fields returns no match |
| 3 | D-03: JournalOp has both UploadFile and MkdirPublish variants | VERIFIED | queue.rs:18-54 confirms both variants with correct fields |
| 4 | D-04 (happy path): journal.put fsyncs before reply.ok()/reply.entry() | VERIFIED | read_ops.rs:844 put < line 894 reply.ok(); write_ops.rs:534 put < line 655 reply.entry(); windows/write_ops.rs:910 put < line 967 spawn |
| 4b | D-04 (error path fuser): handle_release acks reply.ok() when journal.put fails | FAILED | read_ops.rs:956-964: Err arm calls handle.cleanup() then falls through to reply.ok() — acks OS with no journal entry and no upload thread |
| 5 | D-05: plaintext temp cleaned after fsync and before spawn | VERIFIED | read_ops.rs:892 handle.cleanup() after put at 844, before reply.ok() at 894 and spawn at 904; windows:957 before spawn at 967 |
| 6 | D-06: replay fetches CURRENT remote metadata, merges, CAS-publishes; does not unpin live CID | FAILED | fetch_merge_publish_parent (lib.rs:1081-1101) uploads but never publishes IPNS record; returns Ok so entry is removed with no commit; unpins live CID at line 1099 |
| 6b | D-06 (CR-02): UploadFile replay correctly unwraps ECIES key before use | FAILED | lib.rs:1197-1227: ECIES-wrapped key (~117 bytes) is decoded and cast directly to [u8;32] — always fails; key is never unwrapped |
| 7 | D-07: entries are vault-tagged; load_all_for_vault returns only matching vault | VERIFIED | queue.rs:216 filters by vault_root_ipns; test load_all_for_vault_excludes_foreign_vault passes |
| 8 | D-08: replay orders MkdirPublish before UploadFile | VERIFIED | queue.rs:272-285 ordered_for_replay; lib.rs:894 calls it in replay_for_vault |
| 9 | D-09: entries exceeding max_retries park as Failed, never silently dropped | VERIFIED (primitive only) | queue.rs:250-264 record_failure transitions to Failed and keeps on disk; BUT record_failure has zero production callers (CR-07) — the primitive exists but is never invoked |
| 10 | D-10: OS notification fires only when failed > 0; pending-only is silent | VERIFIED (dead code) | sync/mod.rs:39-51 and tray/mod.rs:326-335 are correctly structured; BUT WriteParked is never emitted in production (CR-07 — record_failure uncalled) |
| 11 | D-11a: MkdirConflict arm re-arms debounced publisher; lib.rs drain handles it | VERIFIED | lib.rs:686-691 FsEvent::MkdirConflict inserts parent_ino into mutated_folders and calls queue_publish; write_ops.rs:639 sends signal on conflict |
| 11b | D-11b: journal entry stays until parent publish confirms; WR-05 concern | PARTIAL | Entry retained on conflict (not removed in conflict arm), but the debounced publisher path (flush_publish_queue) has no journal knowledge and never removes the entry on success — entry persists indefinitely and replays on next mount |
| 12 | D-12 (fuser): macOS+Linux share single fuser code path | VERIFIED | fuser path in read_ops.rs + write_ops.rs is the shared path; no platform split |
| 12b | D-12 (WinFsp compile, CR-05): Windows UploadSpawnParams uses correct types | FAILED | windows/write_ops.rs:748-751: ApiConfig (should be ApiClient), Arc<Runtime> (should be Handle), crate::publish_coordinator::PublishCoordinator (module does not exist) |
| 12c | D-12 (Windows replay, CR-06): Windows mount calls replay_for_vault | FAILED | windows/mod.rs: journal constructed and injected but replay_for_vault never called |
| 13 | D-03/CR-03: MkdirPublish journals user-wrapped IPNS key (not TEE-wrapped) | FAILED | write_ops.rs:525 and windows/write_ops.rs:153 set child_ipns_key_hex = encrypted_ipns_for_tee; replay at lib.rs:1135 writes TEE-wrapped key as ipns_private_key_encrypted in FolderEntry |
| 14 | CR-08: journal entry removed only after parent folder pointer is confirmed | FAILED | read_ops.rs:941-943: entry removed after upload_content + UploadComplete send, before debounced publisher commits parent pointer |

**Score:** 9/18 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/sdk/src/queue.rs` | Persist-backed WriteQueue with JournalEntry/JournalOp/JournalEntryStatus | VERIFIED | All types present with correct fields, fsync barrier, vault filter |
| `crates/sdk/src/state.rs` | SyncStatus::WriteParked variant | VERIFIED | state.rs:24-29 WriteParked { pending: u32, failed: u32 } present with tests |
| `crates/fuse/src/lib.rs` | FsEvent enum + journal field + MkdirConflict drain arm + replay_for_vault | PARTIAL | FsEvent, journal field, and drain arm present and correct; replay_for_vault present but broken (CR-01, CR-02, CR-03) |
| `crates/fuse/src/read_ops.rs` | handle_release journal-fsync-before-ack ordering | PARTIAL | Happy path ordering correct (line 844 < 894); error path acks OS even on journal failure (CR-04) |
| `crates/fuse/src/write_ops.rs` | handle_mkdir journal entry + conflict retry signal | PARTIAL | Journal put at line 534 before reply.entry() at 655; MkdirConflict signal at line 639; but child_ipns_key_hex stores TEE-wrapped key (CR-03) |
| `crates/fuse/src/platform/windows/write_ops.rs` | WinFsp cleanup/mkdir journal wiring | PARTIAL | Structure present and mirrors fuser, but UploadSpawnParams has wrong types (CR-05) and TEE key issue (CR-03) |
| `apps/desktop/src-tauri/src/fuse/mod.rs` | journal dir injection + WriteQueue construction + replay call | VERIFIED | cb-journal at data_local_dir, WriteQueue::new(journal_dir, 5), replay_for_vault called at line 233 |
| `apps/desktop/src-tauri/src/fuse/windows/mod.rs` | Journal injection + replay call | PARTIAL | Journal injected (lines 65-72, 361) but replay_for_vault never called (CR-06) |
| `apps/desktop/src-tauri/src/sync/mod.rs` | WriteParked bridge with notify + silent arms | VERIFIED (dead) | Arms correctly structured; but WriteParked is never emitted in production (CR-07) |
| `apps/desktop/src-tauri/src/tray/mod.rs` | send_write_parked_notification + TrayStatus::WriteParked | VERIFIED (dead) | Function exists at line 326; TrayStatus::WriteParked in status.rs; but unreachable (CR-07) |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `read_ops.rs` | `fs.journal.put` | release journals before reply.ok() | VERIFIED (happy path only) | Line 844 put < line 894 reply.ok(); error path at 956-964 falls through to reply.ok() |
| `write_ops.rs` | `upload_tx.send(FsEvent::MkdirConflict` | conflict arm signals retry | VERIFIED | Line 639 sends MkdirConflict on conflict |
| `lib.rs` | `mutated_folders.insert` | drain handles MkdirConflict | VERIFIED | Lines 686-691 insert + queue_publish |
| `fuse/mod.rs` | `WriteQueue::load_all_for_vault + replay_for_vault` | replay on mount (macOS) | PARTIAL | Called at line 233; replay logic broken (CR-01, CR-02, CR-03) |
| `windows/mod.rs` | `replay_for_vault` | replay on mount (Windows) | NOT_WIRED | Never called — CR-06 |
| `windows/write_ops.rs` | `fs.journal.put` | cleanup journals before spawn | PARTIAL | Line 910 before spawn at 967; UploadSpawnParams uses wrong types (CR-05) |
| `windows/write_ops.rs` | `upload_tx.send(FsEvent::MkdirConflict` | mkdir conflict retry | VERIFIED | Line 251 sends MkdirConflict |
| `sync/mod.rs` | `SyncStatus::WriteParked` | bridge fires notification | WIRED but HOLLOW | Code exists and is correct; WriteParked never emitted in production (record_failure uncalled) |

### Data-Flow Trace (Level 4)

| Component | Data Variable | Source | Produces Real Data | Status |
|-----------|--------------|--------|-------------------|--------|
| `replay_for_vault` | parent IPNS record | fetch_merge_publish_parent | NO — no IPNS publish issued; Ok() returned without commit | HOLLOW |
| `send_write_parked_notification` | failed count | SyncStatus::WriteParked | NO — WriteParked never emitted by production code paths | HOLLOW |
| `record_failure` | entry.retries | background upload error handler | NO — background upload error paths only log, never call record_failure | DISCONNECTED |

### Behavioral Spot-Checks

Step 7b: SKIPPED — requires running desktop app with mounted vault. Core logic verified by code reading.

### Probe Execution

No probe scripts found for this phase.

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|---------|
| 2026-06-11-fuse-release-data-loss-before-remote-commit | Plans 01-04 | FUSE release() falsely acks then silently loses data | PARTIAL | Journal fsync-before-ack wired correctly in happy path; error path still acks on journal failure (CR-04); retry/park pipeline dead (CR-07); journal entry removed before parent pointer confirmed (CR-08) |
| 2026-06-11-fuse-mkdir-parent-publish-orphan | Plans 01-04 | mkdir parent-publish conflict orphans child folder | PARTIAL | MkdirConflict signal wired (live-session retry works); but crash recovery via replay cannot complete parent IPNS publish and actively unpins the live CID (CR-01); TEE key journaled instead of user key (CR-03); Windows has no replay at all (CR-06) |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `crates/fuse/src/read_ops.rs` | 964 | `reply.ok()` after journal failure | BLOCKER | OS acked with no journal entry and no upload — silent data loss on journal failure |
| `crates/fuse/src/lib.rs` | 1099 | `unpin_content(api, &resolve.cid)` without prior IPNS publish | BLOCKER | Unpins the live parent CID before publishing replacement — new data-loss risk |
| `crates/fuse/src/lib.rs` | 1089-1101 | `return Ok(())` without IPNS publish; then `journal.remove` | BLOCKER | Journal entry removed with no confirmed remote commit |
| `crates/fuse/src/lib.rs` | 1224-1227 | `try_into::<[u8;32]>()` on ECIES-wrapped key (117 bytes) | BLOCKER | UploadFile replay always errors; no UploadFile entry is ever replayed |
| `crates/fuse/src/write_ops.rs` | 525 | `child_ipns_key_hex: encrypted_ipns_for_tee` | BLOCKER | TEE-wrapped key journaled; replay writes it as user-wrapped key in FolderEntry — folder becomes permanently unpublishable |
| `crates/fuse/src/platform/windows/write_ops.rs` | 748-751 | Wrong types in UploadSpawnParams | BLOCKER | Windows winfsp feature does not compile |
| `crates/sdk/src/sync.rs` | 64 | `WriteQueue::default()` pointing at temp dir | BLOCKER | Daemon cannot see real journal; default dir is never created and wiped on reboot |
| `crates/fuse/src/read_ops.rs` | 941-943 | `journal.remove` before parent folder pointer published | BLOCKER | Orphan window remains: crash between upload success and debounced publish leaves irrecoverable state |
| `apps/desktop/src-tauri/src/fuse/windows/mod.rs` | 66-361 | Journal injected but `replay_for_vault` never called | BLOCKER | Windows replay guarantee absent |

### Human Verification Required

Note: items 2-4 below are blocked by code issues and will not pass until the corresponding gaps are fixed.

### 1. Journal Survival After SIGKILL

**Test:** Copy a file into ~/CipherBox; SIGKILL the desktop process before upload completes; relaunch and remount the same vault.
**Expected:** File replayed on mount and present remotely. The cb-journal/*.json entry should exist before relaunch and be gone after successful replay.
**Why human:** Cannot test crash-and-replay headlessly; requires mounted filesystem and kill/restart cycle.

### 2. Park Notification Render (blocked by CR-07)

**Test:** Force upload failure (stop local API or block network); copy a file; exhaust retries.
**Expected:** OS notification titled "CipherBox Upload Failed" appears in notification center; tray shows "Upload Failed"; journal entry remains on disk with Failed status.
**Why human:** Requires live app, controlled network failure, and OS notification rendering. Also blocked by CR-07 (record_failure has no production callers — retries never increment and entries never park).

### 3. Mkdir Orphan Survival

**Test:** Create a directory while a parent-publish conflict is induced.
**Expected:** New folder survives restart; parent publishes correctly with no orphan.
**Why human:** Requires inducing a parent-publish conflict in a live session.

### 4. Ciphertext-Only Journal

**Test:** After creating a journal entry in a live session, open the cb-journal/*.json file.
**Expected:** Only base64/hex values (ciphertext, wrapped keys, IVs, IPNS names) — never readable file content or paths.
**Why human:** Requires creating a live journal entry.

### Gaps Summary

Phase 43 correctly implements the journal primitive (Plan 01) and the fsync-before-ack ordering in the happy path on both fuser and WinFsp. The live-session conflict retry signal (FsEvent::MkdirConflict) is also correctly wired.

However, the replay half of the phase — the mechanism that closes the original UAT bugs after a crash — has eight interlocking blockers:

**Group 1: Replay cannot complete a parent IPNS publish (CR-01, CR-02, CR-03)**
The parent IPNS private key is not journaled, so `fetch_merge_publish_parent` cannot sign and publish the IPNS record. It currently returns `Ok()`, causing journal entries to be removed with no confirmed remote commit. It also unpins the live parent CID before publishing a replacement, risking making the parent folder unfetchable. Additionally, `UploadFile` entries with a key always fail because the ECIES-wrapped key (~117 bytes) cannot be cast to `[u8;32]`. And `MkdirPublish` entries journal the TEE-wrapped IPNS key rather than the user-wrapped key, so replay writes the wrong key into folder metadata.

**Group 2: Windows platform incomplete (CR-05, CR-06)**
The Windows `UploadSpawnParams` struct has wrong field types (`ApiConfig` instead of `ApiClient`, `Arc<Runtime>` instead of `Handle`, wrong module path for `PublishCoordinator`), so the winfsp feature does not compile. Additionally, the Windows mount path never calls `replay_for_vault`.

**Group 3: Retry/park/notification pipeline is dead code (CR-07)**
`record_failure` is called only from unit tests. Background upload failures only log an error. `SyncDaemon` uses `WriteQueue::default()` which points at a temp directory unrelated to the real journal. The tray notification and `WriteParked` status are unreachable.

**Group 4: Premature journal removal (CR-04, CR-08)**
The fuser release error path acks `reply.ok()` when the journal fsync fails. The journal entry is removed after `upload_content` succeeds but before the parent folder pointer is published via the debounced publisher — a crash in this window leaves an irrecoverable orphan with an empty journal.

---

_Verified: 2026-06-12T20:30:00Z_
_Verifier: Claude (gsd-verifier)_
