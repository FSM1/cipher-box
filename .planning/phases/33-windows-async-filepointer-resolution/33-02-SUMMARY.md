---
phase: 33-windows-async-filepointer-resolution
plan: 02
subsystem: desktop
tags: [rust, fuse, winfsp, async, filepointer, ntstatus, polling]

# Dependency graph
requires:
  - phase: 33-windows-async-filepointer-resolution
    plan: 01
    provides: PendingFilePointer struct, drain_file_pointer_completions(), resolving_file_pointers HashSet, file_pointer_tx/rx channels
provides:
  - Windows WinFsp open/read/readdir callbacks drain FilePointer completions on entry
  - Read-while-resolving poll loop with 5s timeout for in-flight FilePointer resolution
  - STATUS_DEVICE_NOT_READY (0xC00000A3) NTSTATUS helper for transient error signaling
affects: [Explorer auto-retry on transient errors, macOS Phase 32 similar drain pattern]

# Tech tracking
tech-stack:
  added: []
  patterns: [FilePointer resolution poll with mutex drop/reacquire for cooperative waiting, STATUS_DEVICE_NOT_READY for Explorer auto-retry]

key-files:
  created: []
  modified:
    - crates/fuse/src/platform/windows/operations.rs
    - crates/fuse/src/platform/windows/read_ops.rs
    - crates/fuse/src/platform/windows/dir_ops.rs

key-decisions:
  - 'Use STATUS_DEVICE_NOT_READY (0xC00000A3) not STATUS_IO_DEVICE_ERROR for poll timeout -- Explorer treats it as transient and retries automatically'
  - 'Mutable local variables (let mut cid, ...) for in-place update after FilePointer resolution completes, avoiding code duplication'
  - 'Poll loop uses 100ms sleep intervals with mutex drop/reacquire to allow resolution tasks to complete'

patterns-established:
  - 'FilePointer read-while-resolving: poll drain_file_pointer_completions in loop, check file_meta_resolved flag, update local vars in-place'
  - 'Transient NTSTATUS: STATUS_DEVICE_NOT_READY signals Explorer to retry without user-visible error'

requirements-completed: []

# Metrics
duration: 3min
completed: 2026-03-28
---

# Phase 33 Plan 02: Windows WinFsp FilePointer Drain + Read-While-Resolving Summary

**Windows WinFsp callbacks drain FilePointer completions on entry; handle_read polls 5s for in-flight resolution and returns STATUS_DEVICE_NOT_READY on timeout for Explorer auto-retry**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-28T20:45:41Z
- **Completed:** 2026-03-28T20:49:05Z
- **Tasks:** 1
- **Files modified:** 3

## Accomplishments

- Added STATUS_DEVICE_NOT_READY (0xC00000A3) NTSTATUS helper to operations.rs for transient error signaling to Explorer
- Wired drain_file_pointer_completions() into all three Windows WinFsp callback entry points (handle_open, handle_read, handle_read_directory)
- Implemented read-while-resolving poll loop in handle_read: when cid is empty and resolution is in-flight, polls every 100ms for up to 5s, then returns STATUS_DEVICE_NOT_READY on timeout
- Used mutable local variables for cid/key/iv/mode to allow in-place update after FilePointer resolution completes without duplicating content-fetch logic

## Task Commits

Each task was committed atomically:

1. **Task 1: Add STATUS_DEVICE_NOT_READY helper and drain calls to Windows callbacks** - `24e65a72d` (feat)

## Files Created/Modified

- `crates/fuse/src/platform/windows/operations.rs` - Added status_device_not_ready() NTSTATUS helper function
- `crates/fuse/src/platform/windows/read_ops.rs` - Added drain_file_pointer_completions() to handle_open and handle_read, added FilePointer resolution poll loop with 5s timeout, made cid locals mutable for post-resolution update
- `crates/fuse/src/platform/windows/dir_ops.rs` - Added drain_file_pointer_completions() to handle_read_directory

## Decisions Made

- Used STATUS_DEVICE_NOT_READY (0xC00000A3) instead of STATUS_IO_DEVICE_ERROR for the poll timeout -- Explorer treats this as a transient condition and retries automatically, which is the desired UX for FilePointers still resolving
- Made cid/encrypted_file_key_hex/iv_hex/encryption_mode mutable locals so the poll loop can update them in-place after resolution, avoiding duplication of the entire content-fetch code path
- Poll interval of 100ms balances responsiveness with lock contention; 5s max wait matches the existing content-fetch poll timeout in the same function

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All Windows WinFsp callback paths now handle async FilePointer resolution non-blockingly
- Phase 33 is complete -- both infrastructure (plan 01) and callback wiring (plan 02) are done
- macOS Phase 32 can follow the same drain_file_pointer_completions() pattern in its FUSE callback handlers

## Self-Check: PASSED

- All 3 modified files exist on disk
- Commit 24e65a72d (Task 1) exists

---

_Phase: 33-windows-async-filepointer-resolution_
_Completed: 2026-03-28_
