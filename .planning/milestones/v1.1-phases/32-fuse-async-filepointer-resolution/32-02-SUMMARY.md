---
phase: 32
plan: 2
status: complete
started: 2026-03-28T04:10:00Z
completed: 2026-03-28T04:20:00Z
duration_minutes: 10
tasks_completed: 2
tasks_total: 2
---

# Summary: 32-02 Refactor drain_refresh_completions to Spawn Async FilePointer Resolution

## What was built

Replaced the synchronous blocking FilePointer resolution loop with async task spawning:

1. **Removed block_with_timeout()** call for FilePointer resolution in drain_refresh_completions()
2. **Async task spawning** via self.rt.spawn() for each unresolved FilePointer
3. **Scoped resolution** using get_unresolved_file_pointers_for_parent(refresh.ino) instead of get_unresolved_file_pointers() to avoid resolving with wrong folder key
4. **Dedup guard** checking resolving_file_pointers before spawning
5. **NETWORK_TIMEOUT** (10s) per task instead of blocking the FUSE thread
6. **drain_filepointer_completions()** called in handle_readdir (macOS), handle_lookup (macOS), and handle_read_directory (Windows)

### Performance impact

Before: O(N * 10s) worst case for N files in a folder during refresh (sequential blocking)
After: O(10s) worst case (all N files resolve concurrently, results drained on next callback)

## Key files

### Modified
- `crates/fuse/src/lib.rs` -- drain_refresh_completions refactored to async
- `crates/fuse/src/dir_ops.rs` -- drain_filepointer_completions added to readdir
- `crates/fuse/src/read_ops.rs` -- drain_filepointer_completions added to lookup
- `crates/fuse/src/platform/windows/dir_ops.rs` -- drain_filepointer_completions added

## Self-Check: PASSED

- No block_with_timeout in FilePointer resolution path
- Async tasks use NETWORK_TIMEOUT (10s)
- Dedup guard prevents duplicate spawns
- Results flow through PendingFilePointer channel
- cargo check --features fuse passes
