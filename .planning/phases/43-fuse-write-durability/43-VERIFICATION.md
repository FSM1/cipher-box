---
phase: 43-fuse-write-durability
verified: 2026-06-13T05:00:00Z
status: passed
score: 18/18 must-haves verified
overrides_applied: 0
human_verification_completed:
  date: 2026-06-14
  confirmed_by: user
  result: "All 4 manual UAT items (SIGKILL replay, park notification, mkdir-orphan survival, ciphertext-only journal) verified on macOS, Linux, and Windows; automated headless UAT passed on all platforms."
re_verification:
  previous_status: gaps_found
  previous_score: 9/18
  gaps_closed:
    - "CR-01: fetch_merge_publish_parent signs and publishes parent IPNS record via journaled user-wrapped key; returns Err on Conflict so entry is retained; unpin_content and record_publish only on Success"
    - "CR-02: replay_upload_entry ecies-unwraps file IPNS key before [u8;32] cast; stores journaled hex as-is without double-wrap"
    - "CR-03: MkdirPublish journals user-ECIES-wrapped child IPNS key on both fuser and Windows; replay_mkdir_entry writes it as-is"
    - "CR-04: fuser handle_release Err arm replies reply.error(libc::EIO) and returns — no fall-through to trailing reply.ok()"
    - "CR-05: UploadSpawnParams uses Arc<cipherbox_api_client::ApiClient>, tokio::runtime::Handle, Arc<crate::PublishCoordinator>"
    - "CR-06: Windows mount calls cipherbox_fuse::replay_for_vault before CipherBoxFS construction with seeded PublishCoordinator"
    - "CR-07: record_failure called from background upload failure path on both fuser and Windows; SyncDaemon receives real cb-journal WriteQueue; WriteParked emitted from on-disk Failed counts; tray/notification pipeline reachable"
    - "WriteQueue::default removed; ordered_for_replay sorts by created_at_ms; 0o600 atomic perms + parent dir fsync at put/remove"
    - "CR-08 Windows residual (fixed post-verification by orchestrator, commit 293de3f4c): Windows upload thread no longer removes journal entries at all — mechanism b replay-only cleanup, matching fuser; cargo check clean, zero winfsp project-code errors"
  gaps_remaining: []
  regressions: []
human_verification:
  - test: "Journal survival after SIGKILL"
    expected: "Copy a file into ~/CipherBox, SIGKILL desktop before upload completes, relaunch. File should replay on mount and be present remotely. The cb-journal entry should disappear after successful replay."
    why_human: "Cannot test crash-and-replay headlessly; requires running desktop app, actual filesystem mount, and kill/restart cycle"
  - test: "Park notification render"
    expected: "Force upload failure (stop API), copy a file, exhaust retries. OS notification titled with failed-upload count appears. Tray shows WriteParked status. Journal entry remains on disk with Failed status."
    why_human: "Requires live app, controlled network failure, and OS notification rendering"
  - test: "Mkdir orphan survival"
    expected: "mkdir with parent-publish conflict; folder survives restart, parent publishes correctly, no orphan"
    why_human: "Requires inducing a parent-publish conflict in a live session"
  - test: "Ciphertext-only journal check"
    expected: "Open any cb-journal/*.json file; contains only base64/hex ciphertext, wrapped keys, IVs, IPNS names — never readable file content"
    why_human: "Requires creating a journal entry with a known file in a live session"
---

# Phase 43: FUSE Write Durability Verification Report

**Phase Goal:** Make FUSE writes durable: persisted out-of-callback pending-upload journal so `release()` no longer falsely acks then silently loses data, and mkdir parent-publish conflicts actually enqueue a retry instead of orphaning the child folder.
**Verified:** 2026-06-13T05:00:00Z
**Status:** passed (human verification completed 2026-06-14 — see `human_verification_completed`)
**Re-verification:** Yes — round 2 after gap closure (plans 43-05..43-08)

## Goal Achievement

The eight blockers from round 1 are substantially resolved. The replay path now publishes parent IPNS records with the correct keys, the fuser error path replies EIO, the Windows path compiles and calls replay on mount, and the park/notify pipeline is live end-to-end. One partial deviation remains on the Windows path (CR-08 mechanism), documented below as a WARNING. Human verification is required to confirm crash-recovery and park-notification behavior at runtime.

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|---------|
| 1 | D-01: WriteQueue is persist-backed in crates/sdk/src/queue.rs | VERIFIED | queue.rs:JournalEntry with PathBuf journal_dir, put/remove/load_all_for_vault, sync_all() barrier |
| 2 | D-02: Journal entries carry stable identifiers, NO ino/parent_ino | VERIFIED | queue.rs:JournalOp fields use IPNS names; test at line 446 asserts no "parent_ino" key in serialized JSON |
| 3 | D-03: JournalOp has both UploadFile and MkdirPublish variants with parent_ipns_key_hex | VERIFIED | queue.rs:18-73 both variants; parent_ipns_key_hex field present with doc comment at lines 37-41 and 67-69 |
| 4 | D-04 (happy path): journal.put fsyncs before reply.ok()/reply.entry() | VERIFIED | read_ops.rs:867 put < 918 reply.ok(); write_ops.rs:549 put < reply.entry(); windows/write_ops.rs:910 put < spawn |
| 4b | D-04 (error path fuser): handle_release Err arm replies EIO and returns | VERIFIED | read_ops.rs:994-1005: Err arm calls reply.error(libc::EIO); return — both Ok (line 992 return) and Err (line 1004 return) paths have explicit return statements; trailing reply.ok() at 1010 is not reachable from either |
| 5 | D-05: plaintext temp cleaned after fsync and before spawn | VERIFIED | read_ops.rs:916 handle.cleanup() after put at 867, before reply.ok() at 918 and spawn at 929 |
| 6 | D-06: replay fetches CURRENT remote metadata, merges, CAS-publishes; does not unpin live CID prematurely | VERIFIED | lib.rs:1053-1183: fetch_merge_publish_parent fetches current remote, signs parent IPNS record with create_ipns_record, CAS-publishes with expected_sequence_number; unpin_content only on Success at line 1163; returns Err on Conflict |
| 6b | D-06 (CR-02): UploadFile replay correctly unwraps ECIES key | VERIFIED | lib.rs:1313-1316: ecies::unwrap_key on wrapped key before try_into::<[u8;32]> at 1344; lib.rs:1398-1400 stores journaled hex as-is, no re-wrap |
| 7 | D-07: entries are vault-tagged; load_all_for_vault returns only matching vault | VERIFIED | queue.rs:216 filters by vault_root_ipns (unchanged from round 1) |
| 8 | D-08: replay orders MkdirPublish before UploadFile, sorted by created_at_ms | VERIFIED | queue.rs:301-326 ordered_for_replay partitions by op type then stable-sorts each group by created_at_ms ascending (WR-01) |
| 9 | D-09/D-10: retry/park/notification pipeline end-to-end | VERIFIED | record_failure called at read_ops.rs:983 and windows/write_ops.rs:1043; sync.rs:137-154 reads load_all_for_vault and emits WriteParked when failed > 0; sync/mod.rs:42-49 fires send_write_parked_notification with count-only copy |
| 10 | D-03/CR-03: MkdirPublish journals user-ECIES-wrapped child IPNS key | VERIFIED | write_ops.rs:529-531 child_ipns_key_hex_user_wrapped = wrap_key(&ipns_private_key, &fs.public_key); windows/write_ops.rs:152-154 same; replay_mkdir_entry writes it as-is at lib.rs:1234 |
| 11 | D-11a: MkdirConflict arm re-arms debounced publisher | VERIFIED | lib.rs:686-691 unchanged from round 1 (confirmed not regressed) |
| 11b | D-11b: journal entry stays until parent publish confirms (fuser) | VERIFIED | read_ops.rs:967-975: CR-08 mechanism b — no removal in upload thread; entry stays until replay on next mount confirms child in parent metadata |
| 12 | D-12 (fuser): macOS+Linux use single fuser code path | VERIFIED | Unchanged from round 1 |
| 12b | D-12 (WinFsp compile, CR-05): UploadSpawnParams uses correct types | VERIFIED | windows/write_ops.rs:758-776: api: Arc<cipherbox_api_client::ApiClient>, rt: tokio::runtime::Handle, coordinator: Arc<crate::PublishCoordinator> |
| 12c | D-12 (Windows replay, CR-06): Windows mount calls replay_for_vault | VERIFIED | windows/mod.rs:347-372: PublishCoordinator seeded from initial_sequences, then cipherbox_fuse::replay_for_vault called before CipherBoxFS construction |
| 13 | CR-08 Windows: journal entry removal gated on confirmed parent pointer publish | VERIFIED | Fixed post-verification (commit 293de3f4c): `spawn_journal.remove` eliminated from the Windows upload thread entirely — mechanism b replay-only cleanup, matching fuser read_ops.rs. grep confirms zero `spawn_journal.remove` occurrences in windows/write_ops.rs; record_failure arm retained; cargo check -p cipherbox-fuse clean and winfsp feature has zero project-code errors. |

**Score:** 17/18 truths verified (1 partial/WARNING)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/sdk/src/queue.rs` | JournalEntry/JournalOp with parent_ipns_key_hex; ordered_for_replay by created_at_ms; 0o600 atomic perms; no Default impl | VERIFIED | All present: parent_ipns_key_hex on both variants (lines 42, 69); ordered_for_replay sorts by created_at_ms (lines 304-326); OpenOptionsExt::mode(0o600) at line 154; no impl Default for WriteQueue |
| `crates/fuse/src/lib.rs` | fetch_merge_publish_parent with IPNS publish + CAS; replay functions with ecies::unwrap_key; BFS resolve_folder_key | VERIFIED | fetch_merge_publish_parent signs and publishes at lines 1129-1182; ecies::unwrap_key in replay_mkdir_entry:1221, replay_upload_entry:1283+1315; BFS descent at lines 1007-1050 with MAX_RESOLVE_DEPTH=32 |
| `crates/fuse/src/read_ops.rs` | handle_release: EIO on prepare failure; parent IPNS key journaled; removal deferred to replay; record_failure on background failure | VERIFIED | EIO at line 1003; parent_ipns_key_hex set at lines 809-853; no removal in upload thread (mechanism b, line 967-975); record_failure at line 983 |
| `crates/fuse/src/write_ops.rs` | handle_mkdir: user-wrapped child IPNS key + parent_ipns_key_hex journaled | VERIFIED | child_ipns_key_hex_user_wrapped from wrap_key at line 529; parent_ipns_key_hex_for_journal at line 523; both set in MkdirPublish entry at lines 539-541 |
| `crates/fuse/src/platform/windows/write_ops.rs` | Correct UploadSpawnParams types; user-wrapped keys; gated removal; record_failure | PARTIAL-WARNING | Types correct (lines 759-762); user-wrapped keys confirmed (lines 148-164); record_failure at line 1043; removal gated on per-file publish only (not parent-pointer), leaving residual orphan window for files without per-file IPNS key |
| `apps/desktop/src-tauri/src/fuse/windows/mod.rs` | replay_for_vault before CipherBoxFS; PublishCoordinator seeded | VERIFIED | PublishCoordinator seeded at lines 349-358; replay_for_vault called at lines 363-372 before CipherBoxFS construction at line 374 |
| `apps/desktop/src-tauri/src/sync/mod.rs` | create_sync_daemon takes WriteQueue; WriteParked fires notification | VERIFIED | create_sync_daemon takes write_queue param at line 29, forwards to SyncDaemon::new at line 59; WriteParked arm at lines 42-49 fires send_write_parked_notification with count-only neutral copy |
| `apps/desktop/src-tauri/src/commands/sync.rs` | Constructs cb-journal WriteQueue and passes to create_sync_daemon | VERIFIED | lines 35-38: data_local_dir().join("cipherbox").join("cb-journal"); WriteQueue::new(journal_dir, 5); passed to create_sync_daemon at line 49 |
| `crates/sdk/src/sync.rs` | SyncDaemon takes WriteQueue (no default); sync_cycle emits WriteParked from on-disk counts | VERIFIED | write_queue: WriteQueue field at line 44; SyncDaemon::new takes write_queue param at line 61; sync_cycle calls load_all_for_vault at line 137 and emits WriteParked at line 153 when failed > 0 |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `read_ops.rs:handle_release` | `fs.journal.put` | put < reply.ok() | VERIFIED | line 867 < line 918 |
| `read_ops.rs:Err arm` | `reply.error(libc::EIO)` | CR-04 error path | VERIFIED | line 1003 with return at 1004 |
| `read_ops.rs:background failure` | `journal.record_failure` | CR-07 fuser | VERIFIED | line 983 |
| `lib.rs:fetch_merge_publish_parent` | `publish_ipns` | CAS via expected_sequence_number | VERIFIED | line 1154 with Success/Conflict match |
| `lib.rs:replay_mkdir_entry` | `ecies::unwrap_key` | parent key unwrap | VERIFIED | line 1221 |
| `lib.rs:replay_upload_entry` | `ecies::unwrap_key` | file + parent key unwrap | VERIFIED | lines 1283 and 1315 |
| `windows/mod.rs` | `cipherbox_fuse::replay_for_vault` | Windows mount replay | VERIFIED | lines 363-372 |
| `windows/write_ops.rs:UploadSpawnParams` | `Arc<ApiClient>/Handle/Arc<PublishCoordinator>` | correct types | VERIFIED | lines 759-762 |
| `windows/write_ops.rs:background failure` | `record_failure` | CR-07 Windows | VERIFIED | line 1043 |
| `sync.rs:sync_cycle` | `WriteQueue::load_all_for_vault` | CR-07 daemon count | VERIFIED | line 137 |
| `sync/mod.rs:WriteParked arm` | `send_write_parked_notification` | notification bridge | VERIFIED | line 46 |
| `commands/sync.rs` | `WriteQueue::new(cb-journal, 5)` | real journal injection | VERIFIED | lines 35-38 |

### Data-Flow Trace (Level 4)

| Component | Data Variable | Source | Produces Real Data | Status |
|-----------|--------------|--------|-------------------|--------|
| `fetch_merge_publish_parent` | parent IPNS record | resolve_ipns + ecies::unwrap_key + create_ipns_record + publish_ipns | YES — confirmed CAS publish on Success path | FLOWING |
| `sync_cycle WriteParked` | failed count | load_all_for_vault on real cb-journal dir matching commands/sync.rs path | YES — reads real on-disk entries set by record_failure | FLOWING |
| `record_failure` | retries + Failed status | background upload error path in read_ops.rs:983 and windows/write_ops.rs:1043 | YES — production callers present | FLOWING |

### Behavioral Spot-Checks

Step 7b: SKIPPED — requires running desktop app with mounted vault. Core logic verified by code reading. Orchestrator confirmed: 43/43 cipherbox-sdk tests pass, cargo check -p cipherbox-fuse clean (default features), winfsp feature zero project-code errors, desktop build finished.

### Probe Execution

No probe scripts found for this phase.

### Requirements Coverage

| Requirement | Source Plans | Description | Status | Evidence |
|-------------|------------|-------------|--------|---------|
| 2026-06-11-fuse-release-data-loss-before-remote-commit | Plans 01-06,08 | FUSE release() falsely acks then silently loses data | VERIFIED | Journal fsync-before-ack on both platforms; EIO on prepare failure (CR-04); record_failure drives park pipeline (CR-07); fuser entry stays until replay confirms parent-pointer publish (CR-08 mechanism b); daemon reads real journal (CR-07 end-to-end) |
| 2026-06-11-fuse-mkdir-parent-publish-orphan | Plans 01-05,07 | mkdir parent-publish conflict orphans child folder | VERIFIED | Live-session conflict retry via FsEvent::MkdirConflict preserved; replay path signs and publishes parent IPNS record with user-wrapped key (CR-01); correct key in FolderEntry after replay (CR-03); Windows calls replay on mount (CR-06) |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `crates/fuse/src/platform/windows/write_ops.rs` | 1011-1033 | Journal entry removed after per-file IPNS publish (not parent-pointer publish) for UploadFile entries | WARNING | For files without per-file IPNS keys (file_ipns_private_key/file_meta_ipns_name/folder_key_for_file_meta any is None), file_meta_publish_ok stays true and entry is removed after upload_content alone — residual orphan window on Windows. Fuser path uses mechanism (b) (no in-thread removal), which is correct; Windows is a partial implementation. |

No `TBD`, `FIXME`, or `XXX` markers found in any modified file.

### Human Verification Required

#### 1. Journal Survival After SIGKILL

**Test:** Copy a file into ~/CipherBox; SIGKILL the desktop process before upload completes; relaunch and remount the same vault.
**Expected:** File replayed on mount and present remotely. The cb-journal entry should exist before relaunch and be gone after successful replay (fuser: replay removes it; Windows: replay removes it on next mount if entry was retained, or file is already confirmed if per-file publish succeeded).
**Why human:** Cannot test crash-and-replay headlessly; requires mounted filesystem and kill/restart cycle.

#### 2. Park Notification Render

**Test:** Force upload failure (stop local API or block network); copy a file; exhaust retries (max_retries = 5).
**Expected:** OS notification with neutral count-only copy appears (e.g. "1 pending upload(s) failed and require attention."). Tray shows WriteParked status. Journal entry remains on disk with Failed status.
**Why human:** Requires live app, controlled network failure, and OS notification rendering.

#### 3. Mkdir Orphan Survival

**Test:** Create a directory while a parent-publish conflict is induced.
**Expected:** New folder survives restart; parent publishes correctly with no orphan.
**Why human:** Requires inducing a parent-publish conflict in a live session.

#### 4. Ciphertext-Only Journal

**Test:** After creating a journal entry in a live session, open the cb-journal/*.json file.
**Expected:** Only base64/hex values (ciphertext, wrapped keys, IVs, IPNS names) — never readable file content or paths.
**Why human:** Requires creating a live journal entry. Static analysis confirms the D-05 invariant is enforced in the schema and tested (queue.rs:430-454), but runtime confirmation is prudent.

### RESOLVED: Windows CR-08 Partial Implementation

Round-2 verification found the Windows implementation had chosen a hybrid for CR-08 (removal gated on per-file IPNS publish), leaving a residual orphan window for files without per-file IPNS key material — the `if let` at `windows/write_ops.rs:1012` would not match, and the entry was removed after `upload_content` alone, before the debounced parent-pointer publish.

**Resolution (2026-06-13, commit 293de3f4c):** The orchestrator applied the verifier-specified fix — `spawn_journal.remove` removed from the Windows upload thread entirely, mechanism (b) replay-only cleanup, matching `crates/fuse/src/read_ops.rs`. The per-file IPNS publish attempt is retained (live-path optimization); the `record_failure` arm is untouched. Verified: zero `spawn_journal.remove` occurrences in `windows/write_ops.rs`, `cargo check -p cipherbox-fuse` clean, `--features winfsp` zero project-code errors.

### Gaps Summary

All eight round-1 blockers (CR-01..CR-08) are resolved, including the Windows CR-08 residual (fixed post-verification, commit 293de3f4c). The phase goal is achieved on both platforms at the code level: writes are durable behind a fsynced journal, replay correctly publishes parent IPNS records with the right keys, error paths surface failures instead of silently acking, and the park/notify pipeline is live end-to-end. The remaining items are runtime confirmations that require a live desktop session (see Human Verification above).

---

_Verified: 2026-06-13T05:00:00Z_
_Verifier: Claude (gsd-verifier)_
_Re-verification: Round 2 — after gap closure plans 43-05, 43-06, 43-07, 43-08_
