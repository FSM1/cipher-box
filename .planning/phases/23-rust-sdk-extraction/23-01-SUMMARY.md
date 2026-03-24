---
phase: 23-rust-sdk-extraction
plan: 01
subsystem: crypto
tags: [rust, cargo-workspace, aes-gcm, ecies, ed25519, hkdf, ipns]

# Dependency graph
requires:
  - phase: 09-desktop-client
    provides: Desktop Rust crypto modules (aes, ecies, ed25519, hkdf, ipns, utils)
provides:
  - Cargo workspace at repo root with centralized dependency versions
  - cipherbox-crypto crate with 8 modules (aes, aes_ctr, ecies, ed25519, hkdf, ipns_name, utils, error)
  - Unified CryptoError enum for all crypto operations
  - Desktop app rewired to import crypto from workspace crate
affects: [23-02-core-crate, 23-03-metadata-types, 23-04-ipns-operations]

# Tech tracking
tech-stack:
  added: [cipherbox-crypto crate]
  patterns: [cargo workspace with centralized deps, module re-export for backward compat]

key-files:
  created:
    - Cargo.toml (workspace root)
    - crates/crypto/Cargo.toml
    - crates/crypto/src/lib.rs
    - crates/crypto/src/error.rs
    - crates/crypto/src/aes.rs
    - crates/crypto/src/aes_ctr.rs
    - crates/crypto/src/ecies.rs
    - crates/crypto/src/ed25519.rs
    - crates/crypto/src/hkdf.rs
    - crates/crypto/src/ipns_name.rs
    - crates/crypto/src/utils.rs
  modified:
    - apps/desktop/src-tauri/Cargo.toml
    - apps/desktop/src-tauri/src/crypto/mod.rs
    - apps/desktop/src-tauri/src/crypto/ipns.rs
    - apps/desktop/src-tauri/src/crypto/folder.rs
    - apps/desktop/src-tauri/src/crypto/bin.rs

key-decisions:
  - 'Re-export cipherbox_crypto sub-modules in desktop crypto/mod.rs for zero-change backward compat with crate::crypto::aes::* paths'
  - 'Keep ecies as direct desktop dependency because commands/util.rs uses ecies::SecretKey/PublicKey internal types'
  - 'Re-export derive_ipns_name from local ipns.rs for backward compat with test and domain code paths'
  - 'Unified CryptoError enum replaces per-module error types (AesError, AesCtrError, EciesError, Ed25519Error, HkdfError)'

patterns-established:
  - 'Workspace crate extraction pattern: copy modules, update error types, re-export in desktop mod.rs for backward compat'
  - 'Centralized [workspace.dependencies] in root Cargo.toml for version consistency'
  - '[patch.crates-io] lives at workspace root, not in member crates'

requirements-completed: [RSDK-01, RSDK-02]

# Metrics
duration: 13min
completed: 2026-03-24
---

# Phase 23 Plan 01: Workspace and Crypto Crate Extraction Summary

**Cargo workspace established at repo root with cipherbox-crypto crate containing all pure cryptographic primitives; desktop app rewired to use workspace dependency with all 174 tests passing**

## Performance

- **Duration:** 13 min
- **Started:** 2026-03-24T07:13:49Z
- **Completed:** 2026-03-24T07:27:17Z
- **Tasks:** 2
- **Files modified:** 26 (13 created + 13 modified/deleted)

## Accomplishments

- Cargo workspace at repo root with centralized dependency versions for 20+ shared crates
- cipherbox-crypto crate with 8 modules: aes, aes_ctr, ecies, ed25519, hkdf, ipns_name, utils, error
- Desktop app compiles and all 174 tests pass using cipherbox-crypto as a workspace dependency
- 6 duplicated crypto files removed from desktop (net -7744 lines of duplicated code)
- Vendored fuser [patch.crates-io] correctly relocated to workspace root

## Task Commits

Each task was committed atomically:

1. **Task 1: Create Cargo workspace and cipherbox-crypto crate** - `523d3defb` (feat)
2. **Task 2: Rewire desktop app to use cipherbox-crypto workspace crate** - `97d2482e5` (feat)

## Files Created/Modified

- `Cargo.toml` - Workspace root with centralized deps, patch.crates-io
- `Cargo.lock` - Workspace lockfile (moved from desktop)
- `crates/crypto/Cargo.toml` - cipherbox-crypto crate manifest
- `crates/crypto/src/lib.rs` - Crate public API re-exports
- `crates/crypto/src/error.rs` - Unified CryptoError enum
- `crates/crypto/src/aes.rs` - AES-256-GCM encrypt/decrypt/seal/unseal
- `crates/crypto/src/aes_ctr.rs` - AES-256-CTR with range decrypt
- `crates/crypto/src/ecies.rs` - ECIES key wrapping with secp256k1
- `crates/crypto/src/ed25519.rs` - Ed25519 keygen/sign/verify
- `crates/crypto/src/hkdf.rs` - HKDF-SHA256 IPNS keypair derivation
- `crates/crypto/src/ipns_name.rs` - IPNS CIDv1 base36 name derivation
- `crates/crypto/src/utils.rs` - Random bytes, file key gen, MIME detection
- `apps/desktop/src-tauri/Cargo.toml` - Uses workspace crate, removed direct crypto deps
- `apps/desktop/src-tauri/src/crypto/mod.rs` - Re-exports from cipherbox_crypto
- `apps/desktop/src-tauri/src/crypto/ipns.rs` - Removed extracted functions, imports from crate
- `apps/desktop/src-tauri/src/crypto/folder.rs` - Uses CryptoError instead of AesError
- `apps/desktop/src-tauri/src/crypto/bin.rs` - Uses cipherbox_crypto::ecies directly

## Decisions Made

- **Module re-export pattern:** `pub use cipherbox_crypto::aes;` in desktop crypto/mod.rs preserves all existing `crate::crypto::aes::*` paths without touching 50+ call sites across FUSE modules
- **ecies as direct dependency:** Desktop commands/util.rs uses `ecies::SecretKey/PublicKey` internal types for secp256k1 key derivation, requiring the crate as a direct dependency alongside cipherbox-crypto's wrapper
- **derive_ipns_name re-export:** Re-exported from local ipns.rs so `crate::crypto::ipns::derive_ipns_name` paths in tests continue to work without changing test code
- **Unified CryptoError:** Replaces 5 per-module error types with a single enum, using descriptive variants instead of generic "failed" messages

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added ecies as direct desktop dependency**

- **Found during:** Task 2 (desktop compilation)
- **Issue:** `commands/util.rs` uses `ecies::SecretKey` and `ecies::PublicKey` internal types, which are not exposed through cipherbox-crypto's wrapper API
- **Fix:** Added `ecies = { workspace = true }` to desktop Cargo.toml
- **Files modified:** `apps/desktop/src-tauri/Cargo.toml`
- **Verification:** `cargo check -p cipherbox-desktop` passes
- **Committed in:** 97d2482e5 (Task 2 commit)

**2. [Rule 3 - Blocking] Added target/ to root .gitignore**

- **Found during:** Task 1 (workspace creates root-level target/)
- **Issue:** Workspace build artifacts at root `target/` directory not gitignored
- **Fix:** Added `target/` to `.gitignore`
- **Files modified:** `.gitignore`
- **Verification:** `git status` no longer shows target/
- **Committed in:** 523d3defb (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (2 blocking)
**Impact on plan:** Both fixes were necessary for compilation and clean git state. No scope creep.

## Issues Encountered

None - extraction was clean with no unexpected compatibility issues.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Workspace foundation established for all subsequent crate extractions
- Plan 02 (cipherbox-core crate) can now depend on cipherbox-crypto
- Domain modules (folder, bin, vault_blob, ipns) remain in desktop, ready for extraction to cipherbox-core
- All existing desktop functionality preserved with zero behavioral changes

## Self-Check: PASSED

All 11 created files verified present. Both task commits (523d3defb, 97d2482e5) verified in git log.

---

_Phase: 23-rust-sdk-extraction_
_Completed: 2026-03-24_
