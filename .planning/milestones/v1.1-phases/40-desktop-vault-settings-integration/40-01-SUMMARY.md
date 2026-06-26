---
phase: 40-desktop-vault-settings-integration
plan: 01
subsystem: crypto
tags: [hkdf, ed25519, ipns, serde, vault-settings, rust]

# Dependency graph
requires:
  - phase: 39-user-configurable-vault-parameters
    provides: TypeScript VaultSettings type, deriveVaultSettingsIpnsKeypair, validateVaultSettings
provides:
  - derive_vault_settings_ipns_keypair() in cipherbox-crypto crate
  - VaultSettings struct with serde camelCase serialization in cipherbox-core crate
  - default_vault_settings() and validate_vault_settings() functions
  - Cross-language test vector for cipherbox-vault-settings-v1
affects: [40-02-PLAN, desktop-fuse, desktop-settings-sync]

# Tech tracking
tech-stack:
  added: []
  patterns: [HKDF domain-separated derivation, serde camelCase round-trip, cross-language test vectors]

key-files:
  created:
    - crates/core/src/vault_settings.rs
  modified:
    - crates/crypto/src/hkdf.rs
    - crates/crypto/src/lib.rs
    - crates/crypto/tests/cross_language.rs
    - tests/vectors/crypto/hkdf.json
    - crates/core/src/lib.rs

key-decisions:
  - 'Used function default_vault_settings() instead of const DEFAULT_VAULT_SETTINGS since String::new() is not const-stable'
  - 'validate_vault_settings takes &serde_json::Value for flexibility with arbitrary JSON input'
  - 'Negative numeric values in JSON fall back to defaults via as_u64() returning None'

patterns-established:
  - 'HKDF vault-settings derivation: same pattern as vault, vault-key, registry, bin, file'
  - 'VaultSettings camelCase serde: Rust struct mirrors TypeScript type field names exactly'

requirements-completed: []

# Metrics
duration: 4min
completed: 2026-03-31
---

# Phase 40 Plan 01: Crypto Foundation for Desktop Vault Settings Summary

**HKDF vault-settings IPNS derivation in cipherbox-crypto and VaultSettings domain type with validation in cipherbox-core, cross-language parity verified via shared test vectors**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-31T13:29:06Z
- **Completed:** 2026-03-31T13:33:35Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- Added derive_vault_settings_ipns_keypair() to cipherbox-crypto with HKDF info "cipherbox-vault-settings-v1" for domain separation
- Cross-language test vector generated from TypeScript and verified against Rust implementation
- VaultSettings struct with serde camelCase serialization matching TypeScript type exactly
- validate_vault_settings() with clamping (0-365 retention, 0-100 versions, 0-1440 cooldown) and unknown-version guard

## Task Commits

Each task was committed atomically:

1. **Task 1: Add derive_vault_settings_ipns_keypair to crypto crate** - `593f065` (test: TDD RED) + `14675d2` (feat: TDD GREEN)
2. **Task 2: Add VaultSettings type and validation to core crate** - `5f2450b` (feat)

## Files Created/Modified

- `crates/crypto/src/hkdf.rs` - Added VAULT_SETTINGS_HKDF_INFO constant and derive_vault_settings_ipns_keypair() function with 3 unit tests
- `crates/crypto/src/lib.rs` - Added derive_vault_settings_ipns_keypair to re-exports
- `crates/crypto/tests/cross_language.rs` - Added match arm for cipherbox-vault-settings-v1 info string
- `tests/vectors/crypto/hkdf.json` - Added vault settings test vector with expected keys and IPNS name
- `crates/core/src/vault_settings.rs` - New module with VaultSettings struct, DeleteBehavior enum, default_vault_settings(), validate_vault_settings() with 13 unit tests
- `crates/core/src/lib.rs` - Added vault_settings module declaration and re-exports

## Decisions Made

- Used `default_vault_settings()` function instead of `const DEFAULT_VAULT_SETTINGS` because `String::new()` is not const-stable in all Rust editions
- `validate_vault_settings` takes `&serde_json::Value` (not a typed struct) to handle arbitrary/corrupt JSON input gracefully
- Negative numeric values in JSON trigger `as_u64()` returning `None`, which falls back to defaults (matching TypeScript `Number.isFinite` behavior)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- TypeScript tsx runner failed with ESM module resolution error (`ERR_PACKAGE_PATH_NOT_EXPORTED` for @libp2p/crypto). Used vitest runner instead to generate the cross-language test vector.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- cipherbox-crypto exports `derive_vault_settings_ipns_keypair` for Plan 02 desktop integration
- cipherbox-core exports `VaultSettings`, `DeleteBehavior`, `default_vault_settings`, `validate_vault_settings` for Plan 02 desktop usage
- Cross-language parity confirmed: identical keys/IPNS names from same input in both Rust and TypeScript

## Self-Check: PASSED

All 6 files verified present. All 3 commits verified in git log.

---

_Phase: 40-desktop-vault-settings-integration_
_Completed: 2026-03-31_
