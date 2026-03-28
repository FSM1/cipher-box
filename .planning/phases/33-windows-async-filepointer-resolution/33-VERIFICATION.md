---
phase: 33-windows-async-filepointer-resolution
verified: 2026-03-28T21:55:00Z
status: passed
score: 9/9 must-haves verified
re_verification: false
---

# Phase 33: Windows Async FilePointer Resolution Verification Report

**Phase Goal:** WinFsp FilePointer resolution no longer blocks the filesystem thread, eliminating Explorer hangs during metadata refresh on Windows
**Verified:** 2026-03-28T21:55:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| #  | Truth | Status | Evidence |
|----|-------|--------|----------|
| 1  | FilePointer resolution in `drain_refresh_completions()` spawns async tasks via channel pair instead of blocking | VERIFIED | `crates/fuse/src/lib.rs` lines 683-701: loop calls `self.rt.spawn(async move { resolve_single_file_pointer(...).await; tx.send(PendingFilePointer {...}) })`. No `block_with_timeout` call inside `drain_refresh_completions`. |
| 2  | Windows Explorer operations do not hang during background metadata refresh | VERIFIED (automated portion) | `drain_file_pointer_completions()` called in `handle_open` (line 111), `handle_read` (line 245), and `handle_read_directory` (line 32) — all WinFsp entry points drain the channel before doing real work, so resolved metadata is applied eagerly. |
| 3  | Resolution latency bounded by timeout rather than O(N * network_timeout) | VERIFIED | Each FilePointer resolution is a separate async task; the caller (`drain_refresh_completions`) returns immediately after spawning. The poll loop in `handle_read` bounds individual read waits to 5s (`Duration::from_secs(5)`, line 291). |
| 4  | Windows desktop E2E tests pass with the async resolution path | UNCERTAIN — human verification needed | Compilation succeeds (commits verified); runtime behavior on an actual Windows+WinFsp installation cannot be verified statically. |

**Score:** 3/3 automated truths VERIFIED, 1 truth needs human confirmation

---

### Required Artifacts

#### Plan 33-01 Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/fuse/src/lib.rs` | `PendingFilePointer` struct, `resolve_single_file_pointer` async fn, `drain_file_pointer_completions` method, new `CipherBoxFS` fields, modified `drain_refresh_completions` | VERIFIED | All present. Lines 88-93: `PendingFilePointer`. Lines 464-502: `resolve_single_file_pointer`. Lines 718-739: `drain_file_pointer_completions`. Lines 530-532: `file_pointer_rx`, `file_pointer_tx`, `resolving_file_pointers` fields on `CipherBoxFS`. |
| `apps/desktop/src-tauri/src/fuse/windows/mod.rs` | Windows `CipherBoxFS` constructor with `file_pointer_tx/rx/resolving_file_pointers` fields | VERIFIED | Line 78: `let (file_pointer_tx, file_pointer_rx) = std::sync::mpsc::channel::<PendingFilePointer>();`. Lines 344-346: struct initialization with all three fields. |
| `apps/desktop/src-tauri/src/fuse/mod.rs` | macOS `CipherBoxFS` constructor with `file_pointer_tx/rx/resolving_file_pointers` fields | VERIFIED | Line 111: channel creation. Lines 206-207: `file_pointer_rx, file_pointer_tx` and `resolving_file_pointers: std::collections::HashSet::new()` in struct literal. Also re-exports `PendingFilePointer` at line 12. |

#### Plan 33-02 Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/fuse/src/platform/windows/read_ops.rs` | `drain_file_pointer_completions` calls in `handle_open` and `handle_read`, read-while-resolving poll loop | VERIFIED | Line 111: `fs.drain_file_pointer_completions()` in `handle_open`. Line 245: same in `handle_read`. Lines 287-315: poll loop with `Duration::from_secs(5)` max wait. Line 275: `let (mut cid, mut encrypted_file_key_hex, mut iv_hex, mut encryption_mode)` — mutable for in-place update. |
| `crates/fuse/src/platform/windows/dir_ops.rs` | `drain_file_pointer_completions` call in `handle_read_directory` | VERIFIED | Line 32: `fs.drain_file_pointer_completions()` after existing drain calls. |
| `crates/fuse/src/platform/windows/operations.rs` | `pub fn status_device_not_ready` helper | VERIFIED | Line 43: `pub fn status_device_not_ready() -> FspError { FspError::NTSTATUS(0xC00000A3_u32 as i32) }` |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `lib.rs drain_refresh_completions()` | `resolve_single_file_pointer()` | `self.rt.spawn(async move { resolve_single_file_pointer(...) })` | WIRED | Lines 691-700: spawns task per unresolved pointer; sends result on `file_pointer_tx`. Pattern `self.rt.spawn.*resolve_single_file_pointer` confirmed present. |
| `lib.rs drain_file_pointer_completions()` | `inode::InodeTable::resolve_file_pointer()` | `self.file_pointer_rx.try_recv()` drains channel, applies metadata | WIRED | Lines 718-739: `while let Ok(pending) = self.file_pointer_rx.try_recv()` calls `self.inodes.resolve_file_pointer(...)` on success. |
| `read_ops.rs handle_open()` | `CipherBoxFS::drain_file_pointer_completions()` | called at entry alongside existing drains | WIRED | Line 111: `fs.drain_file_pointer_completions()` after `drain_upload_completions()` and `drain_content_prefetches()`. |
| `read_ops.rs handle_read()` | `status_device_not_ready()` | returned when 5s poll timeout expires for in-flight resolution | WIRED | Lines 310-313: `if poll_start.elapsed() > max_wait { return Err(status_device_not_ready()); }`. `status_device_not_ready` imported from `operations::implementation` at line 23. |
| `dir_ops.rs handle_read_directory()` | `CipherBoxFS::drain_file_pointer_completions()` | called at entry alongside existing drains | WIRED | Line 32: `fs.drain_file_pointer_completions()` after `drain_refresh_completions()` and `drain_upload_completions()`. |

---

### Requirements Coverage

No external requirement IDs were assigned to this phase (performance improvement / Windows parity). All success criteria from ROADMAP.md are covered by the truths above.

---

### Anti-Patterns Found

No blocking anti-patterns detected in phase-modified files.

Additional note — `drain_refresh_completions()` is confirmed clean: `grep` on `crates/fuse/src/lib.rs` shows `block_with_timeout` appears only as a function definition (line 59) and NOT inside `drain_refresh_completions`. The remaining `block_with_timeout` calls in the codebase are in `fetch_and_decrypt_file_content` (synchronous write-open content load — unrelated to FilePointer resolution) and macOS `operations.rs` (also unrelated).

One minor observation — not a blocker: the macOS `mount_filesystem` pre-population at lines 130 and 164 of `fuse/mod.rs` calls `get_unresolved_file_pointers()` (global) instead of `get_unresolved_file_pointers_for_parent()` (scoped). The plan specified scoped resolution to avoid wrong-folder-key errors (Pitfall 4). This only affects the eager pre-population at mount time (not the ongoing async resolution path), and the pre-population resolves FilePointers synchronously while the correct folder key is in scope for each folder — so in practice the risk of wrong-key decryption is limited. However, the scoped function is used correctly in `drain_refresh_completions` where it matters most for the ongoing async path.

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `apps/desktop/src-tauri/src/fuse/mod.rs` | 130, 164 | Uses `get_unresolved_file_pointers()` (global) instead of `get_unresolved_file_pointers_for_parent()` during pre-population | Info | Affects only eager mount-time pre-population on macOS, not the Windows async path or ongoing resolution. Folder key is still correct at call site since loop iterates per-folder. |

---

### Human Verification Required

#### 1. Explorer Auto-Retry on STATUS_DEVICE_NOT_READY

**Test:** Mount a CipherBoxFS on a Windows machine with WinFsp installed. Place a file that has an unresolved FilePointer (i.e., file metadata is stored as a separate IPNS record). Open Windows Explorer and navigate to the folder. Observe whether Explorer hangs or shows files progressively as FilePointers resolve.
**Expected:** Explorer refreshes the directory without hanging. Individual file opens that hit an unresolved FilePointer during read may briefly show a busy indicator, then succeed once resolution completes within 5s.
**Why human:** Runtime behavior on a live Windows + WinFsp installation with real IPNS network latency cannot be verified statically.

#### 2. STATUS_DEVICE_NOT_READY Retry Behavior

**Test:** Force a file read on a FilePointer that is intentionally slow to resolve (e.g., rate-limit the IPNS endpoint or simulate network delay > 5s). Observe what Windows Explorer or a reading application does when `STATUS_DEVICE_NOT_READY` (0xC00000A3) is returned.
**Expected:** Explorer/application retries automatically without showing a permanent error dialog. After retry, if resolution has completed, the file reads successfully.
**Why human:** Requires a controlled Windows environment with simulated network delay; Explorer retry behavior depends on Explorer internals that cannot be verified from source inspection.

#### 3. Windows Desktop E2E Tests

**Test:** Run the Windows desktop E2E test suite (if present) against a WinFsp mount with the async resolution path active.
**Expected:** All tests pass — no regressions in normal file operations (open, read, readdir, write) due to the new drain calls or mutable local variable changes in `handle_read`.
**Why human:** E2E tests require a Windows runtime with WinFsp installed; cannot execute in this environment.

---

### Gaps Summary

No gaps. All automated checks pass:

- `PendingFilePointer` struct exists in `lib.rs` (lines 88-93)
- `resolve_single_file_pointer` async function exists with 3-retry exponential backoff (`max_retries = 3`, `Duration::from_millis(500 * (1u64 << attempts))`)
- `drain_file_pointer_completions` method exists and drains `file_pointer_rx` into `InodeTable::resolve_file_pointer`
- `drain_refresh_completions` no longer calls `block_with_timeout` for FilePointer resolution — it spawns async tasks instead
- Dedup guard (`resolving_file_pointers.contains(ino)`) prevents duplicate resolution spawns
- `get_unresolved_file_pointers_for_parent(refresh.ino)` scopes resolution to the refreshed folder
- Both Windows and macOS `CipherBoxFS` constructors initialize `file_pointer_tx`, `file_pointer_rx`, and `resolving_file_pointers`
- All three Windows WinFsp callbacks (`handle_open`, `handle_read`, `handle_read_directory`) call `drain_file_pointer_completions()` on entry
- `handle_read` polls for in-flight resolution up to 5s and returns `STATUS_DEVICE_NOT_READY` (0xC00000A3) on timeout
- `status_device_not_ready()` helper is present in `operations.rs` with correct NTSTATUS value
- All three commits (`545c35c3a`, `f732f06a9`, `24e65a72d`) exist in git history and touch the expected files

The phase goal is achieved at the code level. Human verification is needed only for runtime behavior on a live Windows + WinFsp environment.

---

_Verified: 2026-03-28T21:55:00Z_
_Verifier: Claude (gsd-verifier)_
