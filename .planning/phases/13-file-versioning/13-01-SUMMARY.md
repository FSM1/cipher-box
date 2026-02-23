---
phase: 13-file-versioning
plan: 01
subsystem: crypto
tags: [typescript, rust, serde, file-metadata, versioning, aes-gcm]

# Dependency graph
requires:
  - phase: 12.6-per-file-ipns
    provides: FileMetadata type and per-file IPNS metadata structure
provides:
  - VersionEntry type in TypeScript and Rust
  - FileMetadata with optional versions array (backward compatible)
  - Runtime validator for version entries
affects:
  [
    13-02 version creation service,
    13-03 version history UI,
    13-04 restore logic,
    13-05 retention/pruning,
  ]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'VersionEntry stores full crypto context per version (cid, fileKeyEncrypted, fileIv, size, timestamp, encryptionMode)'
    - 'Optional versions array with backward-compat validation (undefined/missing = no versions)'
    - 'Rust serde skip_serializing_if + default for Option<Vec<VersionEntry>> backward compat'

key-files:
  created: []
  modified:
    - packages/crypto/src/file/types.ts
    - packages/crypto/src/file/metadata.ts
    - packages/crypto/src/file/index.ts
    - packages/crypto/src/index.ts
    - apps/desktop/src-tauri/src/crypto/folder.rs
    - apps/desktop/src-tauri/src/crypto/tests.rs
    - apps/desktop/src-tauri/src/fuse/operations.rs

key-decisions:
  - 'VersionEntry encryptionMode is required (not optional like FileMetadata) -- versions always have explicit mode'
  - 'versions array omitted from return when undefined/empty (not serialized as null/[])'

patterns-established:
  - 'VersionEntry validation pattern: per-entry index in error messages for debugging'
  - 'Rust VersionEntry uses String for encryption_mode (not enum) matching existing FileMetadata pattern'

# Metrics
duration: 5min
completed: 2026-02-19
---

# Phase 13 Plan 01: Version Entry Types Summary

**VersionEntry type added to TypeScript and Rust crypto packages with backward-compatible FileMetadata extension and runtime validator**

## Performance

- **Duration:** 5 min
- **Started:** 2026-02-19T17:39:09Z
- **Completed:** 2026-02-19T17:43:52Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- Added VersionEntry type to TypeScript with full crypto context fields (cid, fileKeyEncrypted, fileIv, size, timestamp, encryptionMode)
- Added optional versions array to FileMetadata in TypeScript with validateVersionEntry runtime validation
- Added matching VersionEntry struct and optional versions field to Rust FileMetadata with serde backward compatibility
- All 225 TypeScript crypto tests and 118 Rust tests pass (zero regressions)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add VersionEntry type and update FileMetadata in TypeScript crypto** - `d6bb6e843` (feat)
2. **Task 2: Add VersionEntry to Rust crypto and update FileMetadata struct** - `6ae5a21a4` (feat)

## Files Created/Modified

- `packages/crypto/src/file/types.ts` - VersionEntry type definition, FileMetadata versions field
- `packages/crypto/src/file/metadata.ts` - validateVersionEntry helper, updated validateFileMetadata
- `packages/crypto/src/file/index.ts` - VersionEntry type export
- `packages/crypto/src/index.ts` - VersionEntry re-export from main package
- `apps/desktop/src-tauri/src/crypto/folder.rs` - Rust VersionEntry struct, FileMetadata versions field
- `apps/desktop/src-tauri/src/crypto/tests.rs` - Updated test FileMetadata constructions with versions: None
- `apps/desktop/src-tauri/src/fuse/operations.rs` - Updated release() FileMetadata construction with versions: None

## Decisions Made

- VersionEntry encryptionMode is required (not optional) -- past versions always record their explicit encryption mode, unlike current FileMetadata which defaults to GCM
- versions array is omitted from serialized output when undefined/empty, preserving clean JSON for non-versioned files

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- VersionEntry type available in both TypeScript (@cipherbox/crypto) and Rust for Plan 02 (version creation service)
- FileMetadata backward compatible -- existing metadata without versions field continues to work
- All existing tests pass, confirming no regressions

---

_Phase: 13-file-versioning_
_Completed: 2026-02-19_
