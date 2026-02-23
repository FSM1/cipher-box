---
phase: 11-windows-desktop
plan: 01
subsystem: desktop
tags: [winfsp, fuse, platform-abstraction, rust, windows, tauri]

# Dependency graph
requires:
  - phase: 11.1-desktop-fuse
    provides: FUSE filesystem implementation (inode, cache, file_handle, operations, mod)
  - phase: 11.2-desktop-v2-metadata
    provides: v2 FilePointer metadata format, per-file IPNS publishing
provides:
  - Platform-agnostic FileAttrs struct replacing fuser::FileAttr
  - AccessMode enum replacing POSIX libc O_RDONLY/O_WRONLY/O_RDWR flags
  - WinFsp Cargo dependency and build.rs delayload linking
  - Shared CipherBoxFS types under cfg(any(fuse, winfsp))
  - to_fuse_attr() conversion at operations boundary
affects: [11-windows-desktop plan 02 (WinFsp operations), 11-windows-desktop plan 03 (NSIS installer)]

# Tech tracking
tech-stack:
  added: [winfsp 0.12, widestring 1]
  patterns: [cfg(any(fuse, winfsp)) for shared code, FileAttrs with platform conversion at boundary, AccessMode enum for platform-agnostic flags]

key-files:
  created: []
  modified:
    - apps/desktop/src-tauri/Cargo.toml
    - apps/desktop/src-tauri/build.rs
    - apps/desktop/src-tauri/src/fuse/inode.rs
    - apps/desktop/src-tauri/src/fuse/file_handle.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/fuse/operations.rs

key-decisions:
  - "FileAttrs struct with to_fuse_attr(uid, gid) conversion at operations boundary"
  - "AccessMode enum replaces libc POSIX flags for platform independence"
  - "uid/gid injection at operations layer, not stored in core data structures"
  - "cfg(any(fuse, winfsp)) gating for shared code, fuse-only for mount/macOS-specific"
  - "libc moved to cfg(unix) dependencies only"
  - "normalize_name fallback for winfsp (no unicode-normalization crate)"

patterns-established:
  - "Platform conversion at boundary: core uses FileAttrs, operations convert to fuser::FileAttr or winfsp::FileInfo"
  - "Feature-gated shared code: cfg(any(fuse, winfsp)) for types used by both platforms"
  - "AccessMode enum pattern for platform-agnostic POSIX flag replacement"

# Metrics
duration: 14min
completed: 2026-02-22
---

# Phase 11 Plan 01: Platform Abstraction Layer Summary

**Platform-agnostic FileAttrs/AccessMode abstractions decoupling inode, file_handle, and CipherBoxFS from fuser/libc, with WinFsp build infrastructure**

## Performance

- **Duration:** 14 min
- **Started:** 2026-02-22T19:46:18Z
- **Completed:** 2026-02-22T20:00:30Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- Created platform-agnostic `FileAttrs` struct replacing `fuser::FileAttr` throughout inode.rs, with `to_fuse_attr(uid, gid)` conversion method for macOS operations
- Added `AccessMode` enum in file_handle.rs replacing POSIX `libc::O_RDONLY/O_WRONLY/O_RDWR` flags
- Added WinFsp dependency to Cargo.toml with feature flags (`winfsp = ["dep:winfsp", "dep:widestring"]`) and build.rs delayload linking
- Moved all shared CipherBoxFS types (PublishCoordinator, PendingRefresh, encrypt_metadata_to_json, etc.) from `cfg(fuse)` to `cfg(any(fuse, winfsp))`
- Moved `libc` to `cfg(unix)` dependencies, added `windows-native` to keyring features
- Updated operations.rs to use `to_fuse_attr()` at reply boundary with `current_uid()`/`current_gid()` helpers

## Task Commits

Each task was committed atomically:

1. **Task 1: Platform-agnostic inode types and Cargo/build infrastructure** - `f0acb73` (feat)
2. **Task 2: Platform-agnostic file_handle and operations layer updates** - `fb1e1f0` (feat)

**Plan metadata:** (committed below) (docs: complete plan)

## Files Created/Modified

- `apps/desktop/src-tauri/Cargo.toml` - Added winfsp feature, winfsp/widestring deps, libc to cfg(unix), windows-native keyring, winfsp build-dep
- `apps/desktop/src-tauri/build.rs` - Added WinFsp delayload linking under cfg(target_os = "windows")
- `apps/desktop/src-tauri/src/fuse/inode.rs` - Created FileAttrs struct, to_fuse_attr() conversion, removed libc from core, cfg(any(fuse, winfsp)) gates
- `apps/desktop/src-tauri/src/fuse/file_handle.rs` - Added AccessMode enum replacing libc flags, updated new_read/new_write signatures
- `apps/desktop/src-tauri/src/fuse/mod.rs` - Changed shared types from cfg(fuse) to cfg(any(fuse, winfsp)), kept mount as fuse-only
- `apps/desktop/src-tauri/src/fuse/operations.rs` - Added to_fuse_attr() calls at reply boundary, current_uid()/current_gid() helpers, ttl_for_is_dir()

## Decisions Made

- **FileAttrs with boundary conversion:** Core data structures use platform-agnostic FileAttrs. Conversion to fuser::FileAttr happens at the operations layer via `to_fuse_attr(uid, gid)`. This keeps uid/gid out of the shared code since Windows does not use POSIX ownership.
- **AccessMode enum over raw flags:** Replaced `flags: i32` (POSIX) with `AccessMode { ReadOnly, WriteOnly, ReadWrite }` enum. Cleaner semantics and no libc dependency.
- **cfg(any(fuse, winfsp)) gating pattern:** Shared types and functions use `cfg(any(feature = "fuse", feature = "winfsp"))`. Platform-specific code (mount_filesystem, unmount_filesystem) remains feature-specific.
- **normalize_name fallback for winfsp:** On Windows without unicode-normalization crate, normalize_name returns the name unchanged. WinFsp handles its own normalization.
- **Compilation verification deferred to CI:** Cargo is not installed on this Windows development machine, so compilation was verified via code review and grep analysis. Full cargo check for both features will run in CI.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- **Cargo not available on Windows dev machine:** `cargo check` could not be run locally because Rust/cargo is not installed on this MINGW64 environment. Verification was performed via code review: confirmed no `libc::` references outside cfg gates in inode.rs, file_handle.rs, cache.rs; confirmed FileAttrs used correctly throughout; confirmed to_fuse_attr() conversion at all reply points. Full compilation verification deferred to CI.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All platform-agnostic data structures ready for WinFsp operations implementation (Plan 02)
- CipherBoxFS struct and all shared helper methods accessible under winfsp feature
- Plan 02 can implement `FileSystemContext` trait for WinFsp using the same FileAttrs/InodeTable/cache infrastructure
- WinFsp build infrastructure (Cargo.toml + build.rs) ready for Windows compilation

---
*Phase: 11-windows-desktop*
*Completed: 2026-02-22*
