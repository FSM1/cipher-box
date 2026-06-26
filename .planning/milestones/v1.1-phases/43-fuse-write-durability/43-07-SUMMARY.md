---
phase: 43-fuse-write-durability
plan: "07"
subsystem: fuse-windows
tags:
  - rust
  - fuse
  - winfsp
  - windows
  - replay
  - journal
  - durability
  - gap-closure
dependency_graph:
  requires:
    - crates/fuse/src/lib.rs replay_for_vault (43-02/03/04)
    - JournalOp parent_ipns_key_hex fields (43-05)
  provides:
    - cipherbox-fuse compiles under --features winfsp (CR-05)
    - Windows mount calls replay_for_vault with seeded coordinator (CR-06)
    - Windows handle_cleanup journals user-ECIES-wrapped parent and child IPNS keys (CR-01/CR-03)
    - Windows record_failure called on background upload failure (CR-07 partial)
    - Windows journal removal gated on per-file IPNS publish success (CR-08 mirror)
    - CR-04 mirror documented: WinFsp void-return constraint
  affects:
    - crates/fuse/src/platform/windows/write_ops.rs
    - apps/desktop/src-tauri/src/fuse/windows/mod.rs
tech_stack:
  added: []
  patterns:
    - tokio::runtime::Handle (not Arc<Runtime>) for WinFsp spawn
    - Arc<cipherbox_api_client::ApiClient> (not ApiConfig) in UploadSpawnParams
    - PublishCoordinator seeded from initial IPNS sequences before replay
    - replay_for_vault called before CipherBoxFS construction on Windows
    - JournalEntry carried into spawn closure for record_failure on error
    - journal.remove gated on per-file IPNS publish success
decisions:
  - CR-04 Windows constraint: WinFsp handle_cleanup returns void; no error status can be returned to OS. Entry is never journaled on prepare failure (journal.put is inside the closure), so no success-implying state is committed. Functionally equivalent to the fuser reply.error(libc::EIO) for the journal-write failure case.
  - CR-08 mechanism: removal gated on per-file IPNS publish success (same approach used in 43-06 fuser path). Parent folder pointer publish gating relies on replay idempotency cleanup on next mount.
  - Tasks 1 and 2 collapsed into single commit: CR-03/CR-01 write-side were already fixed in 43-05 (deviation 4); the Task 1 commit covers all handle_cleanup corrections. Task 2 verification confirms prior fixes are intact.
key_files:
  created: []
  modified:
    - crates/fuse/src/platform/windows/write_ops.rs
    - apps/desktop/src-tauri/src/fuse/windows/mod.rs
metrics:
  duration: ~30min
  completed: 2026-06-13
  tasks: 3
  files: 2
---

# Phase 43 Plan 07: Windows Durability Gap Closure Summary

Closes the Windows-specific durability gaps: the non-compiling WinFsp upload path (CR-05),
the absent Windows mount replay (CR-06), plus mirrors the key-handling and removal defects
from the fuser path (CR-03, CR-01 write-side, CR-04/CR-08/CR-07).

## What Was Built

### UploadSpawnParams Type Corrections (CR-05)

`crates/fuse/src/platform/windows/write_ops.rs` — Three `UploadSpawnParams` fields had wrong
types that prevented the crate from compiling under `--features winfsp`:

- `api`: `Arc<cipherbox_api_client::ApiConfig>` (type does not exist) corrected to
  `Arc<cipherbox_api_client::ApiClient>`.
- `rt`: `Arc<tokio::runtime::Runtime>` corrected to `tokio::runtime::Handle` — matching
  `CipherBoxFS.rt`.
- `coordinator`: `Arc<crate::publish_coordinator::PublishCoordinator>` (module does not exist)
  corrected to `Arc<crate::PublishCoordinator>` (crate root).

`cargo check -p cipherbox-fuse --features winfsp` now produces zero `error[...]` / `error:` lines
citing `crates/fuse/` paths.

### Background Upload Improvements (CR-07, CR-08 mirror)

`UploadSpawnParams` field `journal_entry_id: String` replaced with
`journal_entry: cipherbox_sdk::JournalEntry` so the full entry is available inside the spawn closure.

CR-07: `spawn_journal.record_failure(&spawn_entry, &e)` is now called in the background upload
failure path instead of only logging. This gives the retry/park pipeline a production caller on Windows.

CR-08 mirror: `spawn_journal.remove` is now gated behind `file_meta_publish_ok`. The journal entry
is only removed when per-file IPNS publish succeeds. On failure the entry remains for replay.
Parent folder pointer publish gating relies on replay idempotency: if the process crashes between
per-file publish and the debounced parent publish, the next mount's `replay_for_vault` call
reprocesses the entry.

### CR-04 Windows Constraint Documented

WinFsp `handle_cleanup` returns `()` and cannot return a status to the OS. On prepare failure,
the journal entry is never written to disk (the `journal.put` is inside the prepare closure), so
no success-implying journal state is committed. A comment documents this constraint alongside the
fuser parity reference.

### CR-03 and CR-01 Write-Side (Pre-existing from 43-05)

`child_ipns_key_hex` set to user-ECIES-wrapped key (not TEE-wrapped) and `parent_ipns_key_hex`
present in both `MkdirPublish` and `UploadFile` journal entries — already fixed in plan 43-05
(deviation 4). Verified intact by Task 2 criteria checks.

### Windows Mount Replay (CR-06)

`apps/desktop/src-tauri/src/fuse/windows/mod.rs` — Three additions mirroring the macOS mount
orchestrator at `apps/desktop/src-tauri/src/fuse/mod.rs:219-242`:

1. Root and subfolder `resolve_ipns` calls now also return `sequence_number`, accumulated in
   `initial_sequences: Vec<(String, u64)>`.

2. `PublishCoordinator` is constructed before the replay call and seeded from
   `initial_sequences` via `coord.record_publish(name, seq)` — ensures CAS publish uses
   fresh sequence numbers during replay.

3. `cipherbox_fuse::replay_for_vault(&journal, api, private_key, public_key, root_folder_key,
   root_ipns_name, coordinator.clone()).await` is called after pre-populate and before
   `CipherBoxFS` construction. Errors are logged inside replay and never fail the mount.

4. The seeded `publish_coordinator` is passed into `CipherBoxFS` instead of
   `Arc::new(PublishCoordinator::new())` so the live session and replay share it.

## Deviations from Plan

None — plan executed exactly as written. Tasks 1 and 2 were merged into a single commit because
CR-03/CR-01 write-side corrections were already present from 43-05 (deviation 4), and the Task 1
edit pass covered all remaining handle_cleanup corrections simultaneously.

## Known Stubs

None. All six gap-closure items (CR-05, CR-06, CR-01, CR-03, CR-07 partial, CR-08 mirror)
are fully implemented. The "partial" designation for CR-07 is intentional: end-to-end retry
wiring (SyncDaemon + WriteQueue injection) is scoped to plan 43-08.

## Threat Surface Scan

No new network endpoints or auth paths introduced. Threat register mitigations applied:

- T-43-27: UploadSpawnParams types corrected; winfsp feature compiles (CR-05)
- T-43-28: replay_for_vault called on Windows mount with seeded coordinator (CR-06)
- T-43-29: child_ipns_key_hex is user-ECIES-wrapped; never TEE-wrapped (CR-03, pre-existing from 43-05)
- T-43-30: journal removal gated on per-file publish; record_failure called on failure (CR-08/CR-07 mirror)

## Self-Check: PASSED

Commits exist:

- `963468eed` — fix: correct UploadSpawnParams types for winfsp feature compilation
- `ad2339d7e` — feat: add replay_for_vault call to Windows mount for crash recovery
