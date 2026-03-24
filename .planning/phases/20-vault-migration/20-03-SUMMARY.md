---
phase: 20-vault-migration
plan: 03
subsystem: desktop
tags: [vault, blob-v2, rust, fuse, ecies, hkdf, cross-platform]

# Dependency graph
requires:
  - phase: 20-vault-migration
    plan: 01
    provides: 'Vault blob v2 format spec and TypeScript test vectors for cross-platform parity'
provides:
  - 'Rust vault_blob module with serialize/deserialize/detect for v2 binary format'
  - 'Desktop vault fetch supporting migrated users (null DB keys, IPFS v2 blob read)'
  - 'Desktop root folder publish producing v2 blob format'
  - 'Desktop decrypt path handling both v1 JSON and v2 binary blobs from IPFS'
affects: [20-04, desktop-recovery]

# Tech tracking
tech-stack:
  added: []
  patterns:
    [
      'Rust vault_blob module mirrors TypeScript blob.ts for cross-platform parity',
      'Root vs subfolder publish distinction via inode::ROOT_INO check',
      'v2 blob detection in decrypt path for transparent v1/v2 handling',
    ]

key-files:
  created:
    - apps/desktop/src-tauri/src/crypto/vault_blob.rs
  modified:
    - apps/desktop/src-tauri/src/crypto/mod.rs
    - apps/desktop/src-tauri/src/api/types.rs
    - apps/desktop/src-tauri/src/commands/vault.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/fuse/decrypt.rs

key-decisions:
  - 'detect_blob_version checks first byte only (0x02 = v2, else v1) matching TypeScript'
  - 'Root folder identified by inode::ROOT_INO (value 1) rather than adding is_root to build_folder_metadata return'
  - 'initialize_vault produces v2 blob from day one for new desktop users'
  - 'decrypt_metadata_from_ipfs_public transparently handles both v1 and v2 without caller changes'

patterns-established:
  - 'Root folder publishes: v2 blob (ECIES key header + JSON metadata)'
  - 'Subfolder publishes: v1 JSON (unchanged, no key header needed)'
  - 'Migrated vault fetch: HKDF -> IPNS resolve -> IPFS fetch -> v2 blob parse -> ECIES unwrap'

requirements-completed: [VAULT-06]

# Metrics
duration: 25min
completed: 2026-03-23
---

# Phase 20 Plan 03: Desktop Rust v2 Blob Module and Vault Migration Summary

**Rust vault blob v2 serialize/deserialize with 10 cross-platform tests, desktop vault fetch supporting migrated users via IPFS v2 blob, root folder v2 publish, and transparent v1/v2 decrypt**

## Performance

- **Duration:** 25 min
- **Started:** 2026-03-23T21:18:49Z
- **Completed:** 2026-03-23T21:43:56Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- Rust vault_blob module with byte-identical output to TypeScript (verified via cross-platform hex test vectors)
- Desktop fetch_and_decrypt_vault handles both migrated (null DB keys -> IPFS v2 blob) and non-migrated (DB ECIES hex) users
- Root folder publishes now produce v2 blob format with ECIES-wrapped rootFolderKey in header
- FUSE decrypt path transparently detects and handles both v1 JSON and v2 binary blobs
- New user vault initialization produces v2 blob from the start
- VaultResponse struct updated with nullable encrypted key fields and migrated_at timestamp

## Task Commits

Each task was committed atomically:

1. **Task 1: Rust vault_blob module with unit tests** - `9e43e67e3` (feat -- TDD)
2. **Task 2: Update vault fetch, API types, and root folder publish for v2** - `8deb14b1a` (feat)

## Files Created/Modified

- `apps/desktop/src-tauri/src/crypto/vault_blob.rs` - New module: serialize_vault_blob_v2, deserialize_vault_blob_v2, detect_blob_version, BLOB_V2_VERSION, 10 unit tests
- `apps/desktop/src-tauri/src/crypto/mod.rs` - Added `pub mod vault_blob` declaration
- `apps/desktop/src-tauri/src/api/types.rs` - VaultResponse: encrypted_root_folder_key and encrypted_root_ipns_private_key now Option<String>, added migrated_at
- `apps/desktop/src-tauri/src/commands/vault.rs` - fetch_and_decrypt_vault handles null fields via IPFS v2 blob; initialize_vault produces v2 blob
- `apps/desktop/src-tauri/src/fuse/mod.rs` - encrypt_root_metadata_to_v2_blob helper, spawn_metadata_publish with user_public_key param, ROOT_INO detection at call sites
- `apps/desktop/src-tauri/src/fuse/decrypt.rs` - decrypt_metadata_from_ipfs_public detects v2 blobs and strips header before JSON parsing

## Decisions Made

- Root folder detection uses `folder_ino == inode::ROOT_INO` check at spawn_metadata_publish call sites rather than modifying build_folder_metadata return type -- simpler, less invasive change
- initialize_vault produces v2 blob for new users immediately (not just on migration) -- ensures consistency from day one
- decrypt_metadata_from_ipfs_public handles v2 transparently by stripping the key header -- no caller changes needed for existing FUSE refresh/populate paths
- Zeroizing<Vec<u8>> from HKDF converted to Vec<u8> via .to_vec() for type compatibility with existing state storage

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed Zeroizing type mismatch in IPNS key path**

- **Found during:** Task 2 (fetch_and_decrypt_vault)
- **Issue:** HKDF returns `Zeroizing<Vec<u8>>` but if-else branches expected `Vec<u8>`
- **Fix:** Added `.to_vec()` on the HKDF-derived IPNS key
- **Files modified:** apps/desktop/src-tauri/src/commands/vault.rs
- **Verification:** `cargo check --features fuse` passes
- **Committed in:** 8deb14b1a (Task 2 commit)

**2. [Rule 2 - Missing Critical] Added v2 blob detection to decrypt path**

- **Found during:** Task 2 (reviewing FUSE read path)
- **Issue:** decrypt_metadata_from_ipfs_public only handled v1 JSON -- would fail when reading v2 blobs from IPFS after root folder publishes switched to v2
- **Fix:** Added detect_blob_version check and v2 header stripping in decrypt.rs
- **Files modified:** apps/desktop/src-tauri/src/fuse/decrypt.rs
- **Verification:** `cargo check --features fuse` passes, existing v1 path unchanged
- **Committed in:** 8deb14b1a (Task 2 commit)

**3. [Rule 2 - Missing Critical] Added v2 blob for new user vault init**

- **Found during:** Task 2 (reviewing initialize_vault)
- **Issue:** initialize_vault still produced v1 JSON for new users' initial root metadata
- **Fix:** Added v2 blob wrapping with ECIES key header in initialize_vault
- **Files modified:** apps/desktop/src-tauri/src/commands/vault.rs
- **Verification:** `cargo check --features fuse` passes
- **Committed in:** 8deb14b1a (Task 2 commit)

---

**Total deviations:** 3 auto-fixed (1 bug, 2 missing critical)
**Impact on plan:** All auto-fixes necessary for correctness. No scope creep.

## Issues Encountered

- lint-staged backup/restore cycle caused Task 1 commit to be orphaned (reset HEAD~1 in reflog). Recovered via cherry-pick of the dangling commit. Root cause: lint-staged stash/pop with mixed staged/unstaged changes across desktop Rust and API TypeScript files.
- Pre-existing: 44 compiler warnings in the desktop crate (all pre-existing, unrelated to this plan's changes)

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Desktop Rust fully supports v2 blob read and write
- Ready for Plan 04 (web client v2 blob login read, lazy migration, recovery tool)
- Cross-platform test vectors verified: Rust produces byte-identical output to TypeScript
- All existing folder operations continue working (non-root folders use v1 JSON format)

## Self-Check: PASSED

- All 6 files exist on disk (verified below)
- Both task commits found in git log
- `cargo test vault_blob` passes (10/10 tests)
- `cargo check --features fuse` passes (0 errors, 44 pre-existing warnings)

---

_Phase: 20-vault-migration_
_Completed: 2026-03-23_
