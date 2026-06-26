# Phase 32: FUSE Async FilePointer Resolution - Context

**Gathered:** 2026-03-28
**Status:** Ready for planning

<domain>
## Phase Boundary

Make FilePointer IPNS resolution non-blocking on the macOS FUSE thread. Currently, `drain_refresh_completions()` calls `block_with_timeout()` for each unresolved FilePointer sequentially, stalling the single FUSE-T/SMB callback thread for up to 10s per file. This causes Finder "connection lost" errors when a folder has many files with per-file IPNS metadata.

**Scope:** macOS FUSE-T/SMB backend only. Windows WinFsp changes are deferred to a follow-up phase.

</domain>

<decisions>
## Implementation Decisions

### Resolution Strategy

- **D-01:** Use channel-based async resolution, mirroring the existing content prefetch pattern (`content_rx`/`prefetching` in `lib.rs`). Spawn tokio tasks for IPNS resolve + IPFS fetch, send results back via mpsc channel, drain resolved results in the next FUSE callback.
- **D-02:** Do NOT add a batch IPNS resolve API endpoint — reuse existing per-name resolve with concurrent async tasks.

### Stale Data Handling

- **D-03:** Unresolved FilePointers appear as zero-size placeholder files in Finder. File name and directory entry are visible immediately; size/content become available after async resolution completes.

### Resolution Priority

- **D-04:** Eagerly resolve all unresolved FilePointers as soon as `drain_refresh_completions` discovers them. Spawn async tasks immediately rather than waiting for first access.

### Error Resilience

- **D-05:** Retry failed FilePointer resolutions 3 times with exponential backoff. File stays as zero-size placeholder during retries. Finder remains stable — user sees the file but can't open it until resolved.

### Deduplication Guard

- **D-06:** Add a `resolving_file_pointers: HashSet<u64>` (keyed by inode number) mirroring the existing `prefetching: HashSet<String>` pattern. Insert before spawning async task, remove when channel result is drained.

### Open-While-Resolving Behavior

- **D-07:** When `open()`/`read()` hits an unresolved FilePointer that has an in-flight async resolution, block with a short timeout (~5s) polling the channel for that specific result. If resolved in time, serve the data. If not, return EIO. Finder retries automatically on EIO.

### Claude's Discretion

- Exact exponential backoff parameters (base delay, max retries, jitter)
- Channel buffer sizes for FilePointer resolution mpsc
- Whether to reuse the existing `content_rx` channel or create a separate `filepointer_rx` channel
- Internal implementation of the 5s poll loop in open/read (spin vs condvar vs tokio::sync::watch)

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### FUSE Implementation

- `crates/fuse/src/lib.rs` — Core CipherBoxFs struct, `drain_refresh_completions()` (the blocking code to fix), `block_with_timeout()`, content prefetch channel pattern
- `crates/fuse/src/inode.rs` — `resolve_file_pointer()`, `get_unresolved_file_pointers()`, `get_unresolved_file_pointers_for_parent()`, `populate_folder()` with FilePointer handling
- `crates/fuse/src/read_ops.rs` — `handle_read()`, `handle_lookup()` with prefetch patterns
- `crates/fuse/src/dir_ops.rs` — `handle_readdir()` with background refresh and content prefetch
- `crates/fuse/src/operations.rs` — FUSE callback dispatch (all methods delegate to implementation modules)

### Core Types

- `crates/core/src/folder.rs` — `FilePointer` struct definition, `FolderChild` enum
- `crates/core/src/file.rs` — `FileMetadata` (what IPNS resolution decrypts into)

### API Client

- `crates/api-client/` — `ipns::resolve_ipns()` and `ipfs::fetch_content()` used in resolution

### Existing Patterns to Mirror

- `lib.rs:80` — `PendingContent` enum (Success/Failure channel messages)
- `lib.rs:471` — `prefetching: HashSet<String>` dedup guard
- `lib.rs:648-655` — `drain_content_prefetches()` (the pattern to replicate)

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- **Content prefetch pattern** (`lib.rs:80-90`, `648-655`): `PendingContent` enum + mpsc channel + `HashSet` dedup guard. This exact pattern should be replicated for FilePointer resolution.
- **`block_with_timeout()`** (`lib.rs:59-69`): Can be reused for the open-while-resolving fallback (5s poll).
- **`InodeTable::resolve_file_pointer()`** (`inode.rs:621`): Already exists — takes resolved metadata and updates the inode. No changes needed.
- **`InodeTable::get_unresolved_file_pointers()`** (`inode.rs:662`): Already returns `Vec<(u64, String)>` of (ino, ipns_name) pairs. Ready for async dispatch.

### Established Patterns

- **All FUSE callbacks run on a single thread** (FUSE-T/SMB constraint). Any blocking call stalls Finder.
- **Mutation cooldown** (30s): `mutated_folders` HashMap prevents refresh from overwriting local mutations.
- **Proactive prefetch on readdir**: Content for visible files is prefetched in background tasks (`dir_ops.rs:135-181`).

### Integration Points

- **`drain_refresh_completions()`** (`lib.rs:605-645`): This is the method to modify. Currently resolves FilePointers synchronously; needs to spawn async tasks and drain results separately.
- **`handle_read()`** (`read_ops.rs:236+`): Needs to check if file is unresolved and wait for in-flight resolution.
- **`handle_open()`** (`read_ops.rs:228+`): Same — needs unresolved FilePointer awareness.

</code_context>

<specifics>
## Specific Ideas

- Mirror the content prefetch pattern as closely as possible — same enum/channel/drain structure, just for FilePointer metadata instead of file content
- The user emphasized that Windows changes require a separate machine, so platform-specific code separation is important — keep changes in macOS-specific code paths where possible

</specifics>

<deferred>
## Deferred Ideas

- **Windows WinFsp async FilePointer resolution** — Same blocking pattern exists in `platform/windows/read_ops.rs`. Should be a follow-up phase that can potentially execute in parallel with this macOS phase (platform-specific code paths don't overlap).
- **Batch IPNS resolve API endpoint** — Could reduce round trips for folders with many files. Not needed for Phase 32 but could be a performance optimization later.

</deferred>

---

_Phase: 32-fuse-async-filepointer-resolution_
_Context gathered: 2026-03-28_
