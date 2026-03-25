---
phase: 23-rust-sdk-extraction
plan: 03
subsystem: api, testing
tags: [reqwest, http-client, test-vectors, cross-language, parity, serde, json]

requires:
  - phase: 23-01
    provides: Cargo workspace with cipherbox-crypto crate

provides:
  - cipherbox-api-client crate with typed HTTP client for all desktop API endpoints
  - Shared test vector JSON files in tests/vectors/ for cross-language parity
  - Rust cross-language parity test suite loading shared vectors

affects: [23-04, 23-05, 23-06, 23-07]

tech-stack:
  added: [critical-section, urlencoding]
  patterns: [shared-test-vectors, cross-language-parity-testing, typed-api-client]

key-files:
  created:
    - crates/api-client/Cargo.toml
    - crates/api-client/src/lib.rs
    - crates/api-client/src/client.rs
    - crates/api-client/src/auth.rs
    - crates/api-client/src/ipfs.rs
    - crates/api-client/src/ipns.rs
    - crates/api-client/src/types.rs
    - crates/api-client/src/error.rs
    - tests/vectors/crypto/aes-gcm.json
    - tests/vectors/crypto/ecies.json
    - tests/vectors/crypto/ed25519.json
    - tests/vectors/crypto/hkdf.json
    - tests/vectors/crypto/ipns-name.json
    - tests/vectors/core/vault-blob.json
    - tests/vectors/core/folder-metadata.json
    - tests/vectors/core/ipns-record.json
    - tests/vectors/core/bin-metadata.json
    - crates/crypto/tests/cross_language.rs
  modified:
    - Cargo.toml
    - crates/crypto/Cargo.toml

key-decisions:
  - 'Hand-structured API client crate based on existing desktop code rather than openapi-generator (modest API surface, proven code, no Java/Docker CI dependency)'
  - 'Auth module in api-client wraps HTTP auth endpoints (login/refresh/logout/vault), not Keychain ops (those stay desktop-only)'
  - 'Added critical-section std feature to resolve ecies pure-mode linking when building cipherbox-crypto standalone'
  - 'HKDF test vectors include both vault and vault-key derivation paths (Phase 20 dual IPNS separation)'

patterns-established:
  - 'Shared test vectors pattern: JSON files in tests/vectors/ loadable by both Rust and TypeScript'
  - 'Cross-language parity test pattern: Cargo integration tests in crates/*/tests/ loading shared vectors'
  - 'API client module organization: client.rs (HTTP transport), auth.rs (auth endpoints), ipfs.rs (content ops), ipns.rs (name ops), types.rs (DTOs), error.rs (error enum)'

requirements-completed: [RSDK-03, RSDK-05]

duration: 11min
completed: 2026-03-24
---

# Phase 23 Plan 03: API Client and Cross-Language Test Vectors Summary

**Typed HTTP client crate (cipherbox-api-client) with auth/IPFS/IPNS modules, and 9 shared JSON test vector files powering 5 cross-language parity tests**

## Performance

- **Duration:** 11 min
- **Started:** 2026-03-24T07:31:28Z
- **Completed:** 2026-03-24T07:42:04Z
- **Tasks:** 2
- **Files modified:** 23

## Accomplishments

- Created `cipherbox-api-client` crate with typed async HTTP client for all CipherBox API endpoints used by desktop
- Extracted 9 shared test vector JSON files from inline hex constants into `tests/vectors/` (5 crypto + 4 core)
- Built 5 cross-language parity tests that load shared vectors and verify Rust output matches TypeScript
- HKDF vectors include both vault and vault-key derivation paths (Phase 20 dual IPNS name separation)
- Fixed standalone crypto crate linking by adding critical-section std feature

## Task Commits

Each task was committed atomically:

1. **Task 1: Create cipherbox-api-client crate** - `d168e8e` (feat)
2. **Task 2 RED: Failing cross-language tests** - `c0502e9` (test)
3. **Task 2 GREEN: Shared test vector JSON files** - vector files committed in `49f5abf` (interleaved with 23-02 pre-commit hook)

_Note: The GREEN phase vector files were pulled into the 23-02 commit by the pre-commit hook's lint-staged process. The files are correctly committed and all tests pass._

## Files Created/Modified

- `crates/api-client/Cargo.toml` - API client crate manifest
- `crates/api-client/src/lib.rs` - Public API with module re-exports
- `crates/api-client/src/client.rs` - HTTP client with auth header injection
- `crates/api-client/src/auth.rs` - Login, refresh, logout, vault HTTP operations
- `crates/api-client/src/ipfs.rs` - IPFS fetch, upload, unpin operations
- `crates/api-client/src/ipns.rs` - IPNS resolve and publish with conflict handling
- `crates/api-client/src/types.rs` - DTOs with camelCase serde and redacted Debug
- `crates/api-client/src/error.rs` - ApiError enum with transport/API/auth/deser variants
- `tests/vectors/crypto/aes-gcm.json` - AES-256-GCM encrypt/decrypt vectors
- `tests/vectors/crypto/ed25519.json` - Ed25519 sign/verify with RFC 8032 key
- `tests/vectors/crypto/ecies.json` - ECIES secp256k1 wrap/unwrap vectors
- `tests/vectors/crypto/hkdf.json` - HKDF derivation vectors for all 5 domains
- `tests/vectors/crypto/ipns-name.json` - IPNS name derivation vectors
- `tests/vectors/core/vault-blob.json` - Vault blob v2 format reference
- `tests/vectors/core/folder-metadata.json` - Folder metadata v2 schema reference
- `tests/vectors/core/ipns-record.json` - IPNS record structure reference
- `tests/vectors/core/bin-metadata.json` - Recycle bin metadata v1 reference
- `crates/crypto/tests/cross_language.rs` - 5 cross-language parity tests
- `Cargo.toml` - Added api-client workspace member, critical-section, urlencoding
- `crates/crypto/Cargo.toml` - Added critical-section and serde dev-dependency

## Decisions Made

- Hand-structured API client crate based on existing desktop code rather than openapi-generator (modest ~20-endpoint API surface, proven code, avoids Java/Docker CI dependency)
- Auth module wraps HTTP auth endpoints (login/refresh/logout/vault), not Keychain operations (Keychain stays desktop-only)
- Added `critical-section` with `std` feature to resolve ecies pure-mode linking error when building cipherbox-crypto standalone (the `ecies` crate's `once_cell` dependency requires a critical-section implementation, which Tauri provides when building the desktop app but is absent for standalone crate builds)
- HKDF test vectors include both `cipherbox-vault-ipns-v1` and `cipherbox-vault-key-ipns-v1` derivation paths per plan requirement (Phase 20 dual IPNS separation)
- Core vector files (vault-blob, folder-metadata, ipns-record, bin-metadata) contain schema references rather than encrypt/decrypt pairs since those operations involve non-deterministic IVs or ECIES ephemeral keys

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added critical-section std feature for standalone ecies linking**

- **Found during:** Task 2 (RED phase, test compilation)
- **Issue:** `cipherbox-crypto` crate failed to link standalone due to undefined `__critical_section_1_0_acquire` symbols from the `ecies` crate's `once_cell` dependency. In the desktop app, Tauri provides this implementation.
- **Fix:** Added `critical-section = { version = "1", features = ["std"] }` to workspace deps and crypto crate deps
- **Files modified:** Cargo.toml (root), crates/crypto/Cargo.toml
- **Verification:** `cargo test -p cipherbox-crypto --test cross_language` compiles and runs
- **Committed in:** c0502e9 (Task 2 RED commit)

**2. [Rule 3 - Blocking] Pre-commit hook interleaved 23-02 commits with 23-03 staging**

- **Found during:** Task 2 (GREEN phase, commit attempt)
- **Issue:** The pre-commit hook's lint-staged process detected pending 23-02 changes (crates/core) and committed them, pulling the staged 23-03 vector files into the 23-02 commit
- **Fix:** No fix needed -- vector files are correctly committed and all tests pass. Documented in summary.
- **Impact:** Vector files appear in commit 49f5abf (labeled 23-02) rather than a dedicated 23-03 commit

---

**Total deviations:** 2 auto-fixed (2 blocking)
**Impact on plan:** critical-section fix was necessary for standalone crate building. Commit interleaving is cosmetic only.

## Issues Encountered

None beyond the deviations documented above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `cipherbox-api-client` crate ready for desktop app migration (Plan 23-05 can replace hand-written API code with `use cipherbox_api_client::*`)
- Shared test vectors ready for TypeScript test suite to load (CI parity gate can be added in Plan 23-07)
- Cross-language parity tests provide regression safety for all future crypto changes

## Self-Check: PASSED

All 18 created files verified on disk. All task commits verified in git log.

---

_Phase: 23-rust-sdk-extraction_
_Completed: 2026-03-24_
