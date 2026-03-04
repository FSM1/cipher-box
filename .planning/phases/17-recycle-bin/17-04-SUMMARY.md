---
phase: 17-recycle-bin
plan: 04
subsystem: desktop, crypto
tags: [rust, fuse, ecies, hkdf, ipns, recycle-bin, serde]

# Dependency graph
requires:
  - phase: 17-01
    provides: TypeScript bin crypto primitives (types, HKDF derivation, ECIES encrypt/decrypt)
provides:
  - Rust RecycleBinMetadata, BinEntry, BinItemType serde structs matching TypeScript types
  - derive_bin_ipns_keypair in hkdf.rs with info "cipherbox-recycle-bin-ipns-v1"
  - ECIES encrypt/decrypt for bin metadata in crypto/bin.rs
  - FUSE handle_unlink creates BinEntry with FilePointer (soft-delete for files)
  - FUSE handle_rmdir creates BinEntry with FolderEntry (soft-delete for folders)
  - spawn_bin_entry_publish background helper for bin IPNS publish lifecycle
affects: [17-05 E2E testing]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Bin entry creation in FUSE delete handlers (fire-and-forget background publish)'
    - 'Inline generate_uuid_v4 and guess_mime_type to avoid adding uuid/mime_guess crate deps'
    - 'CIDs remain pinned on delete for recovery; old bin metadata CID unpinned on successful publish'

key-files:
  created:
    - apps/desktop/src-tauri/src/crypto/bin.rs
  modified:
    - apps/desktop/src-tauri/src/crypto/hkdf.rs
    - apps/desktop/src-tauri/src/crypto/mod.rs
    - apps/desktop/src-tauri/src/fuse/write_ops.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs

key-decisions:
  - 'Used inline generate_uuid_v4 (from registry pattern) instead of adding uuid crate dependency'
  - 'Used inline guess_mime_type mapping instead of adding mime_guess crate dependency'
  - 'Bin publish conflict is logged but entry is lost (CID preserved); next delete or web session creates fresh bin state'

patterns-established:
  - 'spawn_bin_entry_publish follows same spawn thread + block_on pattern as spawn_metadata_publish'
  - 'build_folder_path walks inode tree upward for breadcrumb display (safety capped at 20 levels)'

# Metrics
duration: 7min
completed: 2026-03-04
---

# Phase 17 Plan 04: Desktop FUSE Bin Entry Creation Summary

**Rust bin crypto module with ECIES encrypt/decrypt and FUSE unlink/rmdir rewired from permanent delete to soft-delete with bin IPNS publish**

## Performance

- **Duration:** 7 min
- **Started:** 2026-03-04T01:40:58Z
- **Completed:** 2026-03-04T01:47:45Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Created `crypto/bin.rs` with RecycleBinMetadata, BinEntry, BinItemType serde structs byte-compatible with TypeScript types (verified camelCase field mapping)
- Added `derive_bin_ipns_keypair` to hkdf.rs using same HKDF info string as TypeScript (`cipherbox-recycle-bin-ipns-v1`)
- Rewired FUSE `handle_unlink` to capture FilePointer data and create bin entry instead of unpinning CID
- Rewired FUSE `handle_rmdir` to capture FolderEntry data (with ECIES-wrapped IPNS key) and create bin entry instead of unpinning CID
- Added `spawn_bin_entry_publish` background helper that reads existing bin IPNS, appends entry, encrypts, and publishes

## Task Commits

Each task was committed atomically:

1. **Task 1: Add Rust bin crypto module and HKDF derivation** - `858a08dbf` (feat)
2. **Task 2: Wire bin entry creation into FUSE unlink and rmdir** - `01e40a77a` (feat)

## Files Created/Modified

- `apps/desktop/src-tauri/src/crypto/bin.rs` - RecycleBinMetadata, BinEntry, BinItemType serde structs, ECIES encrypt/decrypt, UUID and MIME helpers
- `apps/desktop/src-tauri/src/crypto/hkdf.rs` - Added BIN_HKDF_INFO constant and derive_bin_ipns_keypair function
- `apps/desktop/src-tauri/src/crypto/mod.rs` - Added `pub mod bin` and re-exports
- `apps/desktop/src-tauri/src/fuse/write_ops.rs` - Rewired handle_unlink and handle_rmdir for soft-delete, added build_folder_path
- `apps/desktop/src-tauri/src/fuse/mod.rs` - Added spawn_bin_entry_publish background helper

## Decisions Made

- Used inline `generate_uuid_v4` (copied from registry/mod.rs pattern) instead of adding `uuid` crate. Rationale: avoid new dependency for a simple function; existing pattern already proven.
- Used inline `guess_mime_type` with common extension map instead of adding `mime_guess` crate. Rationale: only needed for best-effort MIME display in bin UI; `application/octet-stream` fallback is acceptable for unknown extensions.
- On bin IPNS publish conflict, the entry is logged as lost but the CID stays pinned. Rationale: the data is preserved (no data loss), and the next delete or web app session will create a fresh bin state. Full conflict resolution (re-fetch, merge, retry) is not worth the complexity for a background fire-and-forget operation.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Desktop FUSE soft-delete is fully wired, producing cross-platform compatible bin entries
- Web app bin UI (Plan 03) can display and restore items deleted from desktop
- Ready for Plan 05 (E2E testing)

---

_Phase: 17-recycle-bin_
_Completed: 2026-03-04_
