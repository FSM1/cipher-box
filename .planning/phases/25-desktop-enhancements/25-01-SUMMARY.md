---
phase: 25-desktop-enhancements
plan: 01
subsystem: desktop
tags: [tee, ipns, fuse, ecies, key-wrapping, desktop]

# Dependency graph
requires:
  - phase: 23-rust-sdk-extraction
    provides: cipherbox-crypto and cipherbox-core crates with wrap_key and IPNS functions
provides:
  - TEE enrollment for per-file IPNS publishes on both Unix and Windows FUSE mounts
  - File IPNS records include encrypted_ipns_private_key on first publish
affects: [25-desktop-enhancements]

# Tech tracking
tech-stack:
  added: []
  patterns: [TEE enrollment on first-publish using is_new_file CID-empty detection]

key-files:
  created: []
  modified:
    - crates/fuse/src/operations.rs
    - crates/fuse/src/read_ops.rs
    - crates/fuse/src/platform/windows/operations.rs
    - crates/fuse/src/platform/windows/write_ops.rs

key-decisions:
  - 'Used existing is_new_file flag (CID empty check) as first-publish signal for TEE enrollment'
  - 'Mirrored folder TEE enrollment pattern exactly (ECIES wrap_key + hex encode) for file publishes'

patterns-established:
  - 'TEE file enrollment: wrap file IPNS private key with TEE public key on first publish, None on subsequent publishes'

requirements-completed: [DESKTOP-02]

# Metrics
duration: 5min
completed: 2026-03-25
---

# Phase 25 Plan 01: TEE File Enrollment Summary

**TEE enrollment for per-file IPNS publishes on both Unix and Windows FUSE mounts using ECIES key wrapping on first publish**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-25T22:45:53Z
- **Completed:** 2026-03-25T22:51:02Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Added TEE public key wrapping to `publish_file_metadata` on Unix (macOS/Linux) and Windows codepaths
- Files created via desktop FUSE mount now have their IPNS private keys wrapped with the TEE public key on first publish, enabling automatic 3-hour TEE republishing
- Subsequent publishes for the same file correctly pass None for TEE fields (no re-enrollment)
- Both platforms share identical TEE enrollment logic, matching the existing folder creation pattern

## Task Commits

Each task was committed atomically:

1. **Task 1: Add TEE enrollment to publish_file_metadata on Unix** - `bf98036ae` (feat)
2. **Task 2: Add TEE enrollment to publish_file_metadata on Windows** - `cb107b0a7` (feat)

## Files Created/Modified

- `crates/fuse/src/operations.rs` - Added tee_public_key, tee_key_epoch, is_first_publish params and ECIES wrapping logic to publish_file_metadata
- `crates/fuse/src/read_ops.rs` - Threaded TEE keys from CipherBoxFS into background upload spawn in release() handler
- `crates/fuse/src/platform/windows/operations.rs` - Mirrored Unix TEE enrollment for Windows publish_file_metadata
- `crates/fuse/src/platform/windows/write_ops.rs` - Computed is_new_file and threaded TEE keys into Windows cleanup handler

## Decisions Made

- Used existing `is_new_file` flag (CID-empty check) as the first-publish signal -- this reuses the already-computed boolean that detects new files by checking if their CID is empty, which maps exactly to "first publish" semantics
- Mirrored the folder TEE enrollment pattern from write_ops.rs:499-506 exactly for file publishes -- same ECIES wrap_key call, same hex encoding, same conditional on TEE key availability

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- `cargo check --features winfsp` cannot compile on macOS due to the winfsp-sys crate requiring Windows registry access. This is expected and noted in the plan's acceptance criteria. The Windows code changes are structurally identical to the Unix path which compiles cleanly.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- TEE file enrollment complete on both platforms
- Ready for plans 02 and 03 of phase 25

---

## Self-Check: PASSED

All 5 files verified present. Both task commits (bf98036ae, cb107b0a7) verified in git log.

---

_Phase: 25-desktop-enhancements_
_Completed: 2026-03-25_
