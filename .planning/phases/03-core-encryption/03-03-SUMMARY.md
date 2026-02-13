---
phase: 03-core-encryption
plan: 03
subsystem: crypto
tags: [vault, hkdf, key-hierarchy, web-crypto-api, ecies, ed25519]

# Dependency graph
requires:
  - phase: 03-01
    provides: AES-GCM encryption, ECIES key wrapping, Ed25519 signing
  - phase: 03-02
    provides: Ed25519 keypair generation, IPNS signing utilities
provides:
  - HKDF-SHA256 key derivation using Web Crypto API
  - Key hierarchy functions (deriveContextKey, generateFolderKey)
  - Vault initialization (initializeVault, encryptVaultKeys, decryptVaultKeys)
  - VaultInit and EncryptedVaultKeys types
  - Complete crypto module API surface (v0.2.0)
affects:
  - 04-vault-operations (uses initializeVault for first sign-in)
  - 05-ipfs-integration (uses vault IPNS keypair for records)
  - 06-folder-operations (uses generateFolderKey)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Async-first key functions (all return Promise)'
    - 'Memory-only vault keys (never persisted to storage)'
    - 'ECIES wrapping for zero-knowledge server storage'
    - 'CipherBox-v1 salt for domain separation'

key-files:
  created:
    - packages/crypto/src/keys/derive.ts
    - packages/crypto/src/keys/hierarchy.ts
    - packages/crypto/src/keys/index.ts
    - packages/crypto/src/vault/types.ts
    - packages/crypto/src/vault/init.ts
    - packages/crypto/src/vault/index.ts
    - packages/crypto/src/__tests__/hierarchy.test.ts
    - packages/crypto/src/__tests__/vault.test.ts
  modified:
    - packages/crypto/src/index.ts

key-decisions:
  - 'HKDF uses CipherBox-v1 salt for domain separation'
  - 'Folder keys are random (not derived from hierarchy)'
  - 'File keys are random per-file (no deduplication per CRYPT-06)'
  - 'Vault keys wrapped with ECIES for zero-knowledge storage'
  - 'IPNS public key stored in plaintext (not secret)'

patterns-established:
  - 'deriveKey() for low-level HKDF, deriveContextKey() for CipherBox contexts'
  - 'initializeVault/encryptVaultKeys/decryptVaultKeys lifecycle'
  - 'VaultInit for in-memory keys, EncryptedVaultKeys for server storage'

# Metrics
duration: 5min
completed: 2026-01-20
---

# Phase 3 Plan 03: Vault Initialization and Key Hierarchy Summary

**Vault initialization with ECIES-wrapped key storage, HKDF key derivation, and key hierarchy management completing the @cipherbox/crypto module v0.2.0**

## Performance

- **Duration:** 5 min
- **Started:** 2026-01-20T18:52:29Z
- **Completed:** 2026-01-20T18:57:25Z
- **Tasks:** 3
- **Files created/modified:** 9

## Accomplishments

- HKDF-SHA256 key derivation using Web Crypto API with domain separation
- Key hierarchy functions for deriving and generating folder/file keys
- Complete vault initialization with encrypt/decrypt round-trip for server storage
- 34 new tests (19 hierarchy + 15 vault) - total 88 tests passing
- Package exports complete crypto API surface at version 0.2.0

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement HKDF key derivation** - `dc5ade6` (feat)
2. **Task 2: Implement key hierarchy functions** - `607f4e2` (feat)
3. **Task 3: Implement vault initialization** - `c7e32fd` (feat)

## Files Created/Modified

### Key Derivation

- `packages/crypto/src/keys/derive.ts` - HKDF-SHA256 using Web Crypto API
- `packages/crypto/src/keys/hierarchy.ts` - deriveContextKey, generateFolderKey
- `packages/crypto/src/keys/index.ts` - Keys module barrel export

### Vault Management

- `packages/crypto/src/vault/types.ts` - VaultInit, EncryptedVaultKeys types
- `packages/crypto/src/vault/init.ts` - initializeVault, encryptVaultKeys, decryptVaultKeys
- `packages/crypto/src/vault/index.ts` - Vault module barrel export

### Main Package

- `packages/crypto/src/index.ts` - Added vault/keys exports, bumped to v0.2.0

### Tests

- `packages/crypto/src/__tests__/hierarchy.test.ts` - 19 tests for key derivation
- `packages/crypto/src/__tests__/vault.test.ts` - 15 tests for vault lifecycle

## Decisions Made

1. **CipherBox-v1 salt for HKDF** - Static salt provides domain separation across all CipherBox key derivations
2. **Folder keys are random** - Per CONTEXT.md, folder keys are randomly generated then ECIES-wrapped (not derived from hierarchy)
3. **File keys random per-file** - Per CRYPT-06, no deduplication - each file gets unique random key
4. **IPNS public key stored plaintext** - Not secret, needed for IPNS name derivation on server
5. **VaultInit vs EncryptedVaultKeys** - Clear separation between in-memory keys and server storage format

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - all tasks executed without blocking issues.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Complete crypto module ready for Phase 4 (Vault Operations)
- API exports include all functions needed for file/folder operations:
  - AES: encryptAesGcm, decryptAesGcm
  - ECIES: wrapKey, unwrapKey
  - Ed25519: generateEd25519Keypair, signEd25519, verifyEd25519
  - IPNS: signIpnsData, IPNS_SIGNATURE_PREFIX
  - Keys: deriveKey, deriveContextKey, generateFolderKey, generateFileKey
  - Vault: initializeVault, encryptVaultKeys, decryptVaultKeys
  - Utils: generateRandomBytes, generateIv, hexToBytes, bytesToHex, clearBytes
  - Types: VaultKey, VaultInit, EncryptedVaultKeys, Ed25519Keypair, CryptoError
- 88 tests covering all crypto operations
- Phase 3 complete - no remaining plans

---

_Phase: 03-core-encryption_
_Completed: 2026-01-20_
