---
phase: 03-core-encryption
plan: 01
subsystem: crypto
tags: [aes-256-gcm, ecies, secp256k1, ed25519, web-crypto-api, eciesjs, noble-hashes]

# Dependency graph
requires:
  - phase: 01-foundation
    provides: TypeScript monorepo structure with @cipherbox/crypto package
provides:
  - AES-256-GCM symmetric encryption/decryption
  - ECIES secp256k1 key wrapping/unwrapping
  - Ed25519 key generation and signing
  - IPNS record signing utilities
  - VaultKey unified type for crypto identity
affects:
  - 03-02 (key hierarchy derivation uses these primitives)
  - 04-vault-operations (file encryption uses AES-GCM)
  - 05-ipfs-integration (IPNS signing uses Ed25519)

# Tech tracking
tech-stack:
  added:
    - eciesjs@^0.4.16
    - '@noble/hashes@^1.7.1'
    - '@noble/ed25519@^2.2.3'
    - vitest@^3.0.5
  patterns:
    - Async-first crypto API (all functions return Promise)
    - Generic error messages to prevent oracle attacks
    - Uint8Array for all binary data (never strings)
    - ArrayBuffer conversion for Web Crypto API compatibility

key-files:
  created:
    - packages/crypto/src/types.ts
    - packages/crypto/src/constants.ts
    - packages/crypto/src/aes/encrypt.ts
    - packages/crypto/src/aes/decrypt.ts
    - packages/crypto/src/ecies/encrypt.ts
    - packages/crypto/src/ecies/decrypt.ts
    - packages/crypto/src/ed25519/keygen.ts
    - packages/crypto/src/ed25519/sign.ts
    - packages/crypto/src/ipns/sign-record.ts
    - packages/crypto/src/utils/encoding.ts
    - packages/crypto/src/utils/memory.ts
    - packages/crypto/src/utils/random.ts
    - packages/crypto/src/__tests__/aes.test.ts
    - packages/crypto/src/__tests__/ecies.test.ts
    - packages/crypto/src/__tests__/ed25519.test.ts
    - packages/crypto/src/__tests__/ipns.test.ts
  modified:
    - packages/crypto/package.json
    - packages/crypto/src/index.ts

key-decisions:
  - 'Use eciesjs for ECIES operations (built on @noble/curves, audited)'
  - 'Convert eciesjs Buffer output to Uint8Array for consistent API'
  - 'ArrayBuffer casting required for TypeScript 5.9 Web Crypto API compatibility'
  - '65-byte uncompressed public keys (0x04 prefix) for secp256k1'
  - "IPNS signature prefix per IPFS spec ('ipns-signature:')"

patterns-established:
  - "Generic error messages: throw CryptoError('Encryption failed') not detailed messages"
  - 'Key size validation before crypto operations'
  - 'Public key format validation (size + 0x04 prefix check)'
  - 'Best-effort memory clearing with explicit limitations documented'

# Metrics
duration: 6min
completed: 2026-01-20
---

# Phase 3 Plan 01: Crypto Primitives Summary

**AES-256-GCM encryption, ECIES secp256k1 key wrapping, and Ed25519 signing using Web Crypto API and eciesjs library with 54 tests passing**

## Performance

- **Duration:** 6 min 17 sec
- **Started:** 2026-01-20T18:36:44Z
- **Completed:** 2026-01-20T18:43:01Z
- **Tasks:** 3
- **Files created/modified:** 22

## Accomplishments

- AES-256-GCM encrypt/decrypt with Web Crypto API (hardware-accelerated)
- ECIES secp256k1 key wrapping using eciesjs library
- Ed25519 key generation and signing for IPNS records
- IPNS record signing utilities following IPFS spec
- Complete test suite: 54 tests covering round-trips, error cases, and security

## Task Commits

Each task was committed atomically:

1. **Task 1: Add crypto dependencies and package structure** - `a3998dd` (feat)
2. **Task 2: Implement AES-256-GCM encryption/decryption** - `893c061` (feat)
3. **Task 3: Implement ECIES key wrapping with eciesjs** - `1b21356` (feat)

## Files Created/Modified

### Core Crypto Modules

- `packages/crypto/src/aes/encrypt.ts` - AES-256-GCM encryption with Web Crypto API
- `packages/crypto/src/aes/decrypt.ts` - AES-256-GCM decryption with auth tag verification
- `packages/crypto/src/ecies/encrypt.ts` - ECIES wrapKey using eciesjs
- `packages/crypto/src/ecies/decrypt.ts` - ECIES unwrapKey with Buffer-to-Uint8Array conversion
- `packages/crypto/src/ed25519/keygen.ts` - Ed25519 keypair generation
- `packages/crypto/src/ed25519/sign.ts` - Ed25519 sign and verify operations
- `packages/crypto/src/ipns/sign-record.ts` - IPNS-specific signing with prefix

### Types and Constants

- `packages/crypto/src/types.ts` - VaultKey, EncryptedData, CryptoError types
- `packages/crypto/src/constants.ts` - Key/IV/tag sizes, algorithm names

### Utilities

- `packages/crypto/src/utils/encoding.ts` - hexToBytes, bytesToHex, concatBytes
- `packages/crypto/src/utils/memory.ts` - clearBytes, clearAll (best-effort)
- `packages/crypto/src/utils/random.ts` - generateRandomBytes, generateFileKey, generateIv

### Tests (54 total)

- `packages/crypto/src/__tests__/aes.test.ts` - 16 AES tests
- `packages/crypto/src/__tests__/ecies.test.ts` - 15 ECIES tests
- `packages/crypto/src/__tests__/ed25519.test.ts` - 14 Ed25519 tests
- `packages/crypto/src/__tests__/ipns.test.ts` - 9 IPNS tests

## Decisions Made

1. **eciesjs for ECIES operations** - Built on audited @noble/curves, single function API, handles ephemeral keys internally
2. **Buffer to Uint8Array conversion** - eciesjs returns Buffer; we convert to Uint8Array for consistent API across the package
3. **ArrayBuffer casting for Web Crypto** - TypeScript 5.9 requires explicit `as ArrayBuffer` cast to satisfy `BufferSource` type
4. **Uncompressed public keys (65 bytes)** - Use 0x04 prefix format for secp256k1, validate both size and prefix
5. **IPNS signature prefix** - Follow IPFS spec exactly: "ipns-signature:" concatenated before CBOR data

## Deviations from Plan

### Auto-added Functionality

**1. [Rule 2 - Missing Critical] Ed25519 signing and IPNS utilities**

- **Found during:** Task 2 (linter/automation added)
- **Issue:** Plan only covered AES and ECIES; Ed25519 and IPNS signing are needed for Phase 5
- **Added:** Ed25519 keygen, sign, verify; IPNS signIpnsData with spec-compliant prefix
- **Files:** ed25519/keygen.ts, ed25519/sign.ts, ipns/sign-record.ts
- **Verification:** 23 additional tests pass
- **Committed in:** 893c061, 1b21356

**Total deviations:** 1 auto-added (missing critical functionality for later phases)
**Impact on plan:** Ed25519/IPNS signing is required infrastructure; proactive addition prevents Phase 5 blockers.

## Issues Encountered

1. **crypto.getRandomValues 65536 byte limit** - Fixed by chunking large test data generation
2. **eciesjs Buffer return type** - Fixed by wrapping with `new Uint8Array(unwrapped)`
3. **TypeScript 5.9 BufferSource type** - Fixed by explicit ArrayBuffer casting for Web Crypto API calls

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- AES-256-GCM and ECIES primitives ready for file encryption (Phase 4)
- Ed25519 signing ready for IPNS records (Phase 5)
- Package exports complete API surface: encrypt, decrypt, wrap, unwrap, sign, verify
- All tests pass, package builds successfully

Ready for: 03-02-PLAN.md (Key Hierarchy Derivation)

---

_Phase: 03-core-encryption_
_Completed: 2026-01-20_
