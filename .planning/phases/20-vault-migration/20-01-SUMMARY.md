---
phase: 20-vault-migration
plan: 01
subsystem: crypto
tags: [vault, blob-v2, binary-format, ecies, uint8array, tdd, cross-platform]

# Dependency graph
requires:
  - phase: 19.1-extract-core-crypto-sdk-as-shared-package
    provides: '@cipherbox/core package with vault/types.ts and vault/index.ts'
provides:
  - 'serializeVaultBlobV2 function for encoding rootFolderKey + metadata into binary blob'
  - 'deserializeVaultBlobV2 function for parsing v2 blobs back to components'
  - 'detectBlobVersion function for distinguishing v1 JSON from v2 binary blobs'
  - 'VaultBlobV2 type for typed component access'
  - 'Cross-platform test vectors (hex) for Rust implementation parity'
affects: [20-02, 20-03, 20-04, desktop-vault-rust]

# Tech tracking
tech-stack:
  added: []
  patterns:
    [
      'Binary envelope format: version-byte + length-prefixed fields',
      'Cross-platform test vectors via hardcoded hex strings',
    ]

key-files:
  created:
    - packages/core/src/vault/blob.ts
    - packages/core/src/__tests__/vault-blob.test.ts
    - packages/core/src/__tests__/vault-blob-vectors.test.ts
  modified:
    - packages/core/src/vault/types.ts
    - packages/core/src/vault/index.ts

key-decisions:
  - 'blob.ts has zero external dependencies (pure byte manipulation) for easy Rust porting'
  - 'detectBlobVersion treats any non-0x02 first byte as v1 for backward compatibility'
  - 'Test vectors use deterministic key bytes (0xAA + 0x00..0x7F) for easy reproduction in Rust'

patterns-established:
  - 'Binary envelope: 0x02 | uint16_BE(key_len) | ECIES_key | AES_GCM_metadata'
  - 'Version detection via first-byte check (0x02 = v2, anything else = v1 JSON)'
  - 'Cross-platform test vectors with exact hex strings for multi-language parity'

requirements-completed: [VAULT-01]

# Metrics
duration: 4min
completed: 2026-03-23
---

# Phase 20 Plan 01: Vault Blob v2 Format Summary

**Pure-byte vault blob v2 binary format with TDD: serialize/deserialize/detect functions in @cipherbox/core, 19 tests including cross-platform hex vectors for Rust parity**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-23T21:10:12Z
- **Completed:** 2026-03-23T21:14:37Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Vault blob v2 binary format implemented: 0x02 | uint16_BE(key_len) | ECIES_key | AES_GCM_metadata
- Full TDD cycle completed (RED then GREEN) with 19 passing tests across 2 test files
- Cross-platform test vectors with exact hex strings ready for Rust implementation
- Zero external dependencies in blob.ts -- pure byte manipulation for easy porting
- No regressions: all 165 @cipherbox/core tests pass

## Task Commits

Each task was committed atomically:

1. **Task 1: Define v2 types and write failing tests** - `cd532acc3` (test -- TDD RED)
2. **Task 2: Implement blob v2 module and make tests pass** - `e863b5c5b` (feat -- TDD GREEN)

## Files Created/Modified

- `packages/core/src/vault/blob.ts` - serializeVaultBlobV2, deserializeVaultBlobV2, detectBlobVersion, BLOB_V2_VERSION
- `packages/core/src/vault/types.ts` - Added VaultBlobV2 type
- `packages/core/src/vault/index.ts` - Re-exports blob functions and VaultBlobV2 type
- `packages/core/src/__tests__/vault-blob.test.ts` - 14 unit tests for serialize/deserialize/detect
- `packages/core/src/__tests__/vault-blob-vectors.test.ts` - 5 cross-platform test vectors with hardcoded hex

## Decisions Made

- blob.ts kept dependency-free (only imports local type) to make Rust porting straightforward
- detectBlobVersion returns 1 for any non-0x02 first byte (not just 0x7B) for robust backward compatibility
- Test vector key uses 0xAA + incrementing 0x00..0x7F pattern for easy manual verification and Rust reproduction

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Pre-existing: other @cipherbox/core test files failed to resolve @cipherbox/crypto until the crypto package was built. This is a pre-existing issue unrelated to this plan's changes. Building crypto first resolved it, and all 165 tests pass.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- blob.ts ready for use by Plan 02 (web client migration) and Plan 03 (API changes)
- VaultBlobV2 type exported for consumers
- Test vectors documented for Rust desktop implementation (Plan 04)

## Self-Check: PASSED

- All 5 created files exist on disk
- Both task commits (cd532acc3, e863b5c5b) found in git log
- All 165 @cipherbox/core tests pass

---

_Phase: 20-vault-migration_
_Completed: 2026-03-23_
