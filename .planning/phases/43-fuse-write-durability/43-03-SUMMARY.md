---
phase: 43-fuse-write-durability
plan: "03"
subsystem: fuse-windows
tags:
  - rust
  - winfsp
  - write-journal
  - durability
  - data-loss-fix
dependency_graph:
  requires:
    - cipherbox-sdk::WriteQueue (from plan 43-01)
    - cipherbox-sdk::JournalEntry
    - cipherbox-sdk::JournalOp
    - cipherbox-sdk::JournalEntryStatus
    - FsEvent enum (from plan 43-02)
    - CipherBoxFS.journal field (from plan 43-02)
  provides:
    - Windows handle_cleanup journal-fsync-before-spawn ordering
    - Windows handle_create mkdir journal-fsync-before-reply + conflict retry signal
  affects:
    - crates/fuse/src/platform/windows/write_ops.rs
tech_stack:
  added: []
  patterns:
    - UploadSpawnParams struct separating prepare+journal phase from spawn phase (Windows)
    - journal-fsync-before-spawn ordering in WinFsp cleanup callback
    - journal-fsync-before-reply ordering in WinFsp mkdir callback
    - conflict retry via mpsc FsEvent::MkdirConflict signal (Windows)
key_files:
  created: []
  modified:
    - crates/fuse/src/platform/windows/write_ops.rs
decisions:
  - UploadSpawnParams defined as a local struct inside the needs_flush block rather than at module level to keep it scoped to the one call site and avoid polluting the module namespace
  - WinFsp cleanup has no explicit reply.ok() — the implicit ack occurs after the callback returns; the fsync barrier (journal.put before spawn) still protects against crash-before-spawn data loss
  - encrypted_folder_key_hex_for_journal clone added before the value is moved into InodeKind::Folder (same pattern as fuser plan deviation 4)
  - parent_ino_for_conflict captured as let binding before spawn closure so u64 is Copy-moved into FsEvent::MkdirConflict send, matching fuser pattern
metrics:
  duration: 12min
  completed: 2026-06-12
  tasks: 2
  files: 1
---

# Phase 43 Plan 03: WinFsp Write Durability — Windows Callback Wiring Summary

Mirrored the fuser durability wiring from Plan 43-02 into the WinFsp callback path. Reordered `handle_cleanup` to journal-fsync-before-spawn (D-04), moved plaintext cleanup before spawn (D-05), journaled `MkdirPublish` before directory reply (D-04), and replaced the false "debounced publish will retry" warning with an actual `FsEvent::MkdirConflict` retry signal (D-11a/b). Both data-loss bugs are now fixed on all three platforms (D-12).

## What Was Built

### Task 1: handle_cleanup reordering (D-04, D-05)

`crates/fuse/src/platform/windows/write_ops.rs`:

New operation order in `handle_cleanup` (non-delete flush branch):

1. Encrypt + wrap_key + clear_bytes (unchanged)
2. Build `JournalEntry` with `JournalOp::UploadFile` using stable IPNS names (`file_meta_ipns_name`, `parent_folder_ipns_name`) — never inode numbers (D-02)
3. `fs.journal.put(&journal_entry)` — fsync to disk (D-04 barrier)
4. `handle.cleanup()` — zeroize+delete plaintext temp file immediately after fsync (D-05), moved ahead of spawn
5. `std::thread::spawn(...)` — background upload; calls `spawn_journal.remove` on confirmed success; does NOT remove on failure (D-09 replay path)

WinFsp-specific note: there is no `reply.ok()` in `handle_cleanup` — the implicit ack occurs after the callback returns. The fsync barrier (step 3 before step 5) is what protects against crash-before-spawn data loss.

`UploadSpawnParams` struct introduced (local to the flush block) to cleanly separate the prepare+journal phase from the spawn phase, matching the fuser pattern.

### Task 2: handle_create mkdir wiring (D-04, D-11a, D-11b)

`crates/fuse/src/platform/windows/write_ops.rs`:

- After `build_folder_metadata(parent_ino)` and before `std::thread::spawn`: build `JournalEntry` with `JournalOp::MkdirPublish { child_ipns_name, child_folder_key_hex, child_ipns_key_hex, parent_folder_ipns_name, name, created_at_ms }` (hex-encoded ECIES-wrapped keys — no raw key material, D-05)
- `fs.journal.put(&mkdir_journal_entry)` fsyncs before the thread spawns, which runs before the `Ok((attr, ino))` return closes the closure and the directory entry is filled (D-04)
- Parent-publish success branch: `journal_for_mkdir.remove(&mkdir_journal_entry_id)` called after coordinator records publish (D-11b)
- Conflict arm replacement: old false "Debounced publish will retry" comment and warn-only body replaced with `upload_tx.send(crate::FsEvent::MkdirConflict { parent_ino: parent_ino_for_conflict })` (D-11a); journal entry is NOT removed on conflict

### Key line ordering (Windows mirror of fuser plan)

`handle_cleanup` ordering:

```
fs.journal.put (line 910)      <-- fsync barrier
handle.cleanup (line 957)      <-- plaintext deleted before spawn
std::thread::spawn (line 967)  <-- upload started
spawn_journal.remove (line 997, inside thread)  <-- removed on success
```

`handle_create` mkdir ordering:

```
build_folder_metadata (line 136)
fs.journal.put (line 162)      <-- fsync barrier inside closure
std::thread::spawn (line 172)  <-- upload thread
Ok((attr, ino)) (line 265)     <-- WinFsp fills file_info after Ok
journal_for_mkdir.remove (line 240, inside thread)  <-- removed on success
upload_tx.send MkdirConflict (line 251, inside thread)  <-- conflict retry signal
```

## Verification

Build-verified only (no Windows host available on macOS CI; runtime crash-recovery is manual per 43-VALIDATION.md).

`cargo check -p cipherbox-fuse --features winfsp` produces zero errors in cipherbox project crates. All remaining errors are in `windows-future` and `windows_registry` registry crates — pre-existing cross-compilation issues on macOS that are unrelated to this plan's changes and were present before plan 43-02 as well.

## Deviations from Plan

None — plan executed exactly as written. The `encrypted_folder_key_hex_for_journal` clone (analogous to fuser plan deviation 4) was anticipated by the plan's reference to that fix.

## Known Stubs

None. Journal wiring is fully implemented for both Windows callbacks. Plan 43-04 (drain owner) will call `record_failure` on upload error to transition to `WriteParked`.

## Threat Surface Scan

No new network endpoints or auth paths introduced. Threat register mitigations implemented:

| Mitigation | Verification |
| ---------- | ------------ |
| T-43-09: `fs.journal.put` precedes `std::thread::spawn` in handle_cleanup | journal.put line 910 < spawn line 967 |
| T-43-10: `handle.cleanup()` at line 957 before spawn at line 967 — plaintext deleted before upload thread starts | confirmed by grep |
| T-43-11: MkdirPublish journaled at line 162 before spawn at 172; `FsEvent::MkdirConflict` at line 251 triggers live-session retry; journal entry cleared only on success (line 240) | confirmed by grep |
| T-43-12: Windows mirrors every fuser change — both platforms now have identical journal ordering | D-12 satisfied |

## Self-Check: PASSED

All created/modified files exist on disk. Both task commits verified in git log (ea49457f7, fddebcc8c).
