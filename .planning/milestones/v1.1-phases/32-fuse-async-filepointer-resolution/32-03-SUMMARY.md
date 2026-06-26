---
phase: 32
plan: 3
status: complete
started: 2026-03-28T04:20:00Z
completed: 2026-03-28T04:30:00Z
duration_minutes: 10
tasks_completed: 1
tasks_total: 1
---

# Summary: 32-03 Handle open/read for Unresolved FilePointers with Poll-Wait Fallback

## What was built

Added graceful handling for file operations on not-yet-resolved FilePointers:

1. **Poll-wait constants**: FILEPOINTER_POLL_TIMEOUT (5s), FILEPOINTER_POLL_INTERVAL (100ms)
2. **handle_open() poll-wait**: Detects unresolved FilePointers (empty CID + file_meta_resolved=false), polls drain_filepointer_completions() in a loop. If resolved in time, proceeds normally. If not, returns EIO for Finder auto-retry.
3. **handle_read() poll-wait**: Same pattern. If resolved and content cached, serves it. If resolved but content not cached, triggers content prefetch and returns EIO for retry.
4. **handle_getattr() drain**: Calls drain_filepointer_completions() so stat results reflect resolved metadata promptly (correct file sizes).
5. **Windows drain calls**: Added drain_filepointer_completions() to Windows open, read, and readdir handlers for consistency (full poll-wait deferred to Phase 33).

## Key files

### Modified
- `crates/fuse/src/read_ops.rs` -- poll-wait in open/read, drain in getattr/lookup
- `crates/fuse/src/platform/windows/read_ops.rs` -- drain in open/read
- `crates/fuse/src/platform/windows/dir_ops.rs` -- drain in readdir

## Deviations

- Plan called for a separate Task 1 (constants + getattr) but combined into single task since changes are straightforward

## Self-Check: PASSED

- FILEPOINTER_POLL_TIMEOUT and FILEPOINTER_POLL_INTERVAL constants exist
- handle_open detects unresolved FilePointers and polls
- handle_read detects unresolved FilePointers, polls, triggers prefetch if needed
- handle_getattr drains filepointer completions
- Windows handlers also drain filepointer completions
- cargo check --features fuse passes
