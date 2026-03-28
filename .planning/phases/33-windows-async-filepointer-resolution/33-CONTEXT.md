# Phase 33: Windows Async FilePointer Resolution - Context

**Gathered:** 2026-03-28
**Status:** Ready for planning

<domain>
## Phase Boundary

Port Phase 32's channel-based async FilePointer resolution to the Windows WinFsp backend. The same blocking pattern exists in `crates/fuse/src/platform/windows/` — `block_with_timeout()` calls during FilePointer resolution stall the WinFsp callback thread, causing Explorer hangs during metadata refresh.

**Scope:** Windows WinFsp backend only. macOS FUSE-T/SMB changes are handled in Phase 32 (can execute in parallel since code paths are platform-specific).

</domain>

<decisions>
## Implementation Decisions

All decisions mirror Phase 32 — this is a direct port of the same pattern to Windows-specific code.

### Resolution Strategy

- **D-01:** Use channel-based async resolution, mirroring the pattern established in Phase 32 (and the existing content prefetch pattern). Spawn tokio tasks for IPNS resolve + IPFS fetch, send results via mpsc channel, drain in next WinFsp callback.

### Stale Data Handling

- **D-02:** Unresolved FilePointers appear as zero-size placeholder files in Explorer. File name and directory entry visible immediately; size/content available after async resolution.

### Resolution Priority

- **D-03:** Eagerly resolve all unresolved FilePointers as soon as refresh completions are drained.

### Error Resilience

- **D-04:** Retry failed resolutions 3 times with exponential backoff. File stays as zero-size placeholder during retries.

### Deduplication Guard

- **D-05:** Add `resolving_file_pointers: HashSet<u64>` (keyed by inode) to prevent duplicate resolution tasks.

### Open-While-Resolving Behavior

- **D-06:** When `read()` hits an unresolved FilePointer with in-flight resolution, block with ~5s timeout. Return appropriate NTSTATUS error on timeout. Explorer retries automatically.

### Claude's Discretion

- Exact WinFsp NTSTATUS error code for unresolved files (STATUS_DEVICE_NOT_READY vs STATUS_IO_DEVICE_ERROR)
- Whether shared code can be extracted to platform-independent module or stays duplicated
- Backoff parameters matching Phase 32

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Windows WinFsp Implementation

- `crates/fuse/src/platform/windows/read_ops.rs` — Windows read operations with blocking prefetch pattern (the code to modify)
- `crates/fuse/src/platform/windows/dir_ops.rs` — Windows readdir with content prefetch
- `crates/fuse/src/platform/windows/operations.rs` — WinFsp callback dispatch, async content download helper
- `crates/fuse/src/platform/windows/write_ops.rs` — Windows write operations with FilePointer construction

### Shared Code

- `crates/fuse/src/lib.rs` — `CipherBoxFs` struct (shared between platforms), `block_with_timeout()`, channel patterns
- `crates/fuse/src/inode.rs` — `resolve_file_pointer()`, `get_unresolved_file_pointers()` (shared)
- `crates/core/src/folder.rs` — `FilePointer` struct definition

### Phase 32 Reference (macOS implementation to mirror)

- `.planning/phases/32-fuse-async-filepointer-resolution/32-CONTEXT.md` — Original decisions and pattern
- Phase 32 PLAN.md files (once created) — Implementation approach to port

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- **Content prefetch pattern** (already in Windows code): `platform/windows/read_ops.rs` has the same `prefetching` HashSet + background task + channel drain pattern as macOS. This confirms the pattern ports cleanly.
- **`CipherBoxFs` struct fields** (`lib.rs`): The `content_rx`, `prefetching`, and channel infrastructure are platform-independent. New FilePointer resolution channels will also be shared.
- **`InodeTable` methods** (`inode.rs`): `resolve_file_pointer()`, `get_unresolved_file_pointers()` are platform-independent. No Windows-specific changes needed.

### Established Patterns

- **WinFsp callbacks run on a thread pool** (unlike FUSE-T's single thread), but blocking still degrades performance by exhausting the pool.
- **Windows uses `winfsp::filesystem` trait** instead of `fuser::Filesystem`. Different callback signatures but same logical operations.
- **NTSTATUS error codes** used instead of POSIX errno.

### Integration Points

- **`platform/windows/read_ops.rs`**: Main file to modify — add FilePointer resolution channel drain and async dispatch.
- **`platform/windows/dir_ops.rs`**: May need FilePointer resolution drain in readdir path (same as macOS).
- **`lib.rs` CipherBoxFs**: New channel fields are platform-independent — added once, used by both platforms.

</code_context>

<specifics>
## Specific Ideas

- Keep changes strictly in `platform/windows/` where possible — this phase should be safe to execute in parallel with Phase 32 on macOS
- If Phase 32 introduces shared abstractions (e.g., a `PendingFilePointer` enum), reuse them rather than duplicating
- Testing must happen on a Windows machine

</specifics>

<deferred>
## Deferred Ideas

None — this phase is tightly scoped as a direct port.

</deferred>

---

_Phase: 33-windows-async-filepointer-resolution_
_Context gathered: 2026-03-28_
