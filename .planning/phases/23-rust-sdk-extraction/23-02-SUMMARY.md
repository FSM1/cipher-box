---
phase: 23-rust-sdk-extraction
plan: 02
subsystem: crypto
tags: [rust, cargo-workspace, cipherbox-core, domain-types, ipns, metadata, vault-blob]

# Dependency graph
requires:
  - phase: 23-01
    provides: Cargo workspace with cipherbox-crypto crate for cryptographic primitives
provides:
  - cipherbox-core crate with 8 modules (folder, file, bin, vault_blob, ipns, registry, decrypt, error)
  - Domain types extracted from desktop app into shared crate
  - Desktop app rewired to import domain logic from workspace crate
affects: [23-03-ipfs-operations, 23-04-fuse-layer, 23-05-testing]

# Tech tracking
tech-stack:
  added: [cipherbox-core crate]
  patterns: [module re-export for backward compat, domain crate layered on crypto crate]

key-files:
  created:
    - crates/core/Cargo.toml
    - crates/core/src/lib.rs
    - crates/core/src/error.rs
    - crates/core/src/folder.rs
    - crates/core/src/file.rs
    - crates/core/src/bin.rs
    - crates/core/src/vault_blob.rs
    - crates/core/src/ipns.rs
    - crates/core/src/registry.rs
    - crates/core/src/decrypt.rs
  modified:
    - Cargo.toml (workspace members + dependency)
    - apps/desktop/src-tauri/Cargo.toml
    - apps/desktop/src-tauri/src/crypto/mod.rs
    - apps/desktop/src-tauri/src/registry/mod.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/fuse/operations.rs
    - apps/desktop/src-tauri/src/fuse/read_ops.rs
    - apps/desktop/src-tauri/src/fuse/dir_ops.rs
    - apps/desktop/src-tauri/src/fuse/windows/mod.rs
    - apps/desktop/src-tauri/src/fuse/windows/operations.rs
    - apps/desktop/src-tauri/src/fuse/windows/dir_ops.rs

key-decisions:
  - 'File module re-exports FileMetadata/FilePointer/VersionEntry from folder.rs since they share AES encryption context'
  - 'Kept FolderError and BinError as local error types (not unified into CoreError) to preserve backward-compatible error paths'
  - 'ciborium moved to dev-dependencies for desktop (only used in IPNS CBOR test verification)'
  - 'crate::fuse::decrypt:: paths updated to crate::crypto::decrypt:: via re-export in crypto/mod.rs'

patterns-established:
  - 'Domain crate layering: crypto <- core (no reverse dependency)'
  - 'Module re-export pattern extended to core crate: pub use cipherbox_core::folder in crypto/mod.rs'

requirements-completed: [RSDK-04]

# Metrics
duration: 10min
completed: 2026-03-24
---

# Phase 23 Plan 02: Core Crate Extraction Summary

**cipherbox-core crate with folder metadata, file metadata, bin metadata, vault blob v2, IPNS records, device registry, and decrypt bridge; desktop app rewired with all 162 tests passing**

## Performance

- **Duration:** 10 min
- **Started:** 2026-03-24T07:31:27Z
- **Completed:** 2026-03-24T07:41:50Z
- **Tasks:** 2
- **Files modified:** 33 (10 created + 17 modified + 6 deleted)

## Accomplishments

- cipherbox-core crate with 8 modules: folder, file, bin, vault_blob, ipns, registry, decrypt, error
- 6 domain files deleted from desktop app (folder.rs, bin.rs, vault_blob.rs, ipns.rs, decrypt.rs, types.rs)
- Desktop app compiles and all 162 tests pass with domain types from external crate
- Dependency chain strictly enforced: crypto <- core (no reverse)
- 12 vault_blob cross-platform tests pass in core crate

## Task Commits

Each task was committed atomically:

1. **Task 1: Create cipherbox-core crate with domain modules** - `2b3514031` (feat)
2. **Task 2: Rewire desktop app to use cipherbox-core** - `49f5abf0a` (feat)

## Files Created/Modified

- `crates/core/Cargo.toml` - cipherbox-core crate manifest
- `crates/core/src/lib.rs` - Public API re-exports for all domain types
- `crates/core/src/error.rs` - CoreError enum with CryptoError conversion
- `crates/core/src/folder.rs` - FolderMetadata, FolderEntry, FilePointer, FileMetadata, VersionEntry types + AES encrypt/decrypt
- `crates/core/src/file.rs` - Re-exports FileMetadata types from folder module
- `crates/core/src/bin.rs` - RecycleBinMetadata, BinEntry types + ECIES encrypt/decrypt
- `crates/core/src/vault_blob.rs` - v2 binary envelope serialize/deserialize with cross-platform tests
- `crates/core/src/ipns.rs` - IPNS record creation, CBOR data, protobuf marshaling
- `crates/core/src/registry.rs` - DeviceRegistry, DeviceEntry, DeviceAuthStatus, DevicePlatform types
- `crates/core/src/decrypt.rs` - decrypt_metadata_from_ipfs_public bridge for IPFS JSON format
- `apps/desktop/src-tauri/src/crypto/mod.rs` - Now purely re-exports from cipherbox-crypto + cipherbox-core
- `apps/desktop/src-tauri/src/registry/mod.rs` - Imports types from cipherbox_core::registry
- `apps/desktop/src-tauri/src/fuse/mod.rs` - Removed decrypt module, updated paths

## Decisions Made

- **File module as re-export:** FileMetadata, FilePointer, VersionEntry are defined in folder.rs (they share the same AES encryption context with parent folder key) and re-exported via file.rs for API convenience
- **Kept FolderError/BinError:** Local error types preserved to maintain backward-compatible error paths through `crate::crypto::folder::FolderError` in existing code. CoreError is available for future unified error handling.
- **ciborium as dev-dependency:** Moved to `[dev-dependencies]` in desktop since only the IPNS CBOR test verification directly decodes CBOR. The core crate has ciborium as a regular dependency.
- **decrypt module path:** Moved from `crate::fuse::decrypt::` to `crate::crypto::decrypt::` (re-exported through crypto/mod.rs) since the decrypt module is domain logic, not FUSE-specific

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added ciborium as dev-dependency for desktop tests**

- **Found during:** Task 2 (test compilation)
- **Issue:** Desktop test `ipns_record_cbor_data_contains_expected_fields` uses `ciborium::from_reader` and `ciborium::Value` directly for CBOR verification
- **Fix:** Added `ciborium = { workspace = true }` to `[dev-dependencies]` in desktop Cargo.toml
- **Files modified:** `apps/desktop/src-tauri/Cargo.toml`
- **Verification:** `cargo test -p cipherbox-desktop` passes
- **Committed in:** 49f5abf0a (Task 2 commit)

**2. [Rule 1 - Bug] Fixed double path substitution in fuse/mod.rs**

- **Found during:** Task 2 (compilation check)
- **Issue:** `crate::fuse::decrypt::` was inside a `crate::crypto::` prefix that got double-replaced to `crate::crypto::crate::crypto::decrypt::`
- **Fix:** Manually corrected to `crate::crypto::decrypt::` on line 387
- **Files modified:** `apps/desktop/src-tauri/src/fuse/mod.rs`
- **Verification:** `cargo check -p cipherbox-desktop` exits 0
- **Committed in:** 49f5abf0a (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 blocking, 1 bug)
**Impact on plan:** Both fixes necessary for compilation and test passing. No scope creep.

## Issues Encountered

None - extraction was clean after fixing the two deviations above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Domain types now available as a shared crate for any Rust consumer
- Plan 03+ can build higher-level abstractions on cipherbox-core
- All existing desktop functionality preserved with zero behavioral changes
- Dependency chain: crypto <- core <- desktop (strict layering)

## Self-Check: PASSED

All 10 created files verified present. Both task commits (2b3514031, 49f5abf0a) verified in git log. All 6 deleted domain files confirmed absent from desktop.

---

_Phase: 23-rust-sdk-extraction_
_Completed: 2026-03-24_
