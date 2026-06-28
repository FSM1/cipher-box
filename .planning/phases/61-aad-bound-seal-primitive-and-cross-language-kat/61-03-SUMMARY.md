---
phase: 61-aad-bound-seal-primitive-and-cross-language-kat
plan: "03"
subsystem: crypto
tags: [crypto, aad, aes-gcm, seal, kat, cross-language, typescript, transplant-resistance]
requires: [61-01, 61-02]
provides: [encryptAesGcmAad, decryptAesGcmAad, sealAesGcmAad, unsealAesGcmAad, seal_vectors, transplant-suite]
affects: [packages/crypto, tests/vectors/crypto/node-aad.json]
tech-stack:
  added: []
  patterns: [TDD red-green, fixed-IV KAT vector, AAD transplant-resistance matrix, Web Crypto additionalData, MIN_SEALED_SIZE guard]
key-files:
  created: []
  modified:
    - packages/crypto/src/aes/encrypt.ts
    - packages/crypto/src/aes/decrypt.ts
    - packages/crypto/src/aes/seal.ts
    - packages/crypto/src/aes/index.ts
    - packages/crypto/src/index.ts
    - tests/vectors/crypto/node-aad.json
    - packages/crypto/src/__tests__/build-node-aad.test.ts
decisions:
  - "encryptAesGcmAad/decryptAesGcmAad thread AAD via AesGcmParams.additionalData — Web Crypto native path (C-03)"
  - "seal_vectors computed from deterministic encryptAesGcmAad (fixed IV) never from sealAesGcmAad (D-01b)"
  - "forged-domain-version test constructs forged AAD by mutating byte 21 of correct AAD (the '1' of v1)"
  - "seal_vectors.length >= 1 guard before KAT loop prevents vacuous pass if array is emptied"
metrics:
  duration: "~11 minutes"
  completed: "2026-06-28"
  tasks_completed: 2
  files_changed: 7
status: complete
---

# Phase 61 Plan 03: TS AAD-Bound Seal Path and Full-Seal KAT Summary

AES-256-GCM AEAD-with-AAD seal path in TypeScript: `encryptAesGcmAad`/`decryptAesGcmAad` (deterministic, IV-as-arg), `sealAesGcmAad`/`unsealAesGcmAad` (fresh random IV), the committed fixed-IV full-seal KAT vector in `node-aad.json`, and the D-02/CRYPTO-03 extended transplant-resistance negative suite.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| RED | Failing tests for sealAesGcmAad, encryptAesGcmAad (TDD gate) | d861146a4 | build-node-aad.test.ts |
| GREEN | Implement encryptAesGcmAad, decryptAesGcmAad, sealAesGcmAad, unsealAesGcmAad + barrels | ce1b33b3c | encrypt.ts, decrypt.ts, seal.ts, aes/index.ts, src/index.ts |
| 2 | seal_vectors KAT + transplant/negative suite | 8e806b3b2 | node-aad.json, build-node-aad.test.ts |

## What Was Built

### `encryptAesGcmAad` — `packages/crypto/src/aes/encrypt.ts`

Mirrors `encryptAesGcm` with one addition: `additionalData: aadBuffer` in the `AesGcmParams` object passed to `crypto.subtle.encrypt`. The AAD is copied to a fresh `ArrayBuffer` (same defensive copy pattern as IV/key/plaintext) before passing to Web Crypto. The GCM auth tag then covers both the ciphertext and the AAD bytes — any AAD mismatch on the decrypt side causes authentication failure.

### `decryptAesGcmAad` — `packages/crypto/src/aes/decrypt.ts`

Mirrors `decryptAesGcm` with `additionalData: aadBuffer` in the `AesGcmParams`. On auth-tag failure (wrong key, wrong AAD, tampered ciphertext, wrong IV) the catch block throws a generic `CryptoError('Decryption failed', 'DECRYPTION_FAILED')` — identical to the non-AAD variant to prevent oracle attacks.

### `sealAesGcmAad` / `unsealAesGcmAad` — `packages/crypto/src/aes/seal.ts`

Both mirror their non-AAD counterparts exactly:

- `sealAesGcmAad(plaintext, key, aad)`: validates key is 32 bytes, mints a fresh 12-byte IV via `generateIv()` (never accepts a caller IV — D-00a), calls `encryptAesGcmAad`, returns `concatBytes(iv, ciphertext)`.
- `unsealAesGcmAad(sealed, key, aad)`: validates key is 32 bytes, checks `sealed.length >= MIN_SEALED_SIZE` (28 bytes = IV + tag), slices `iv = sealed[0..12]` and `ciphertext = sealed[12..]`, delegates to `decryptAesGcmAad`.

Blob layout is the frozen `[IV(12)][ct+tag(16)]` (D-00a). The non-AAD `sealAesGcm`/`unsealAesGcm` remain unchanged (D-00b: additive, not a refactor).

### Barrel exports

`encryptAesGcmAad`, `decryptAesGcmAad`, `sealAesGcmAad`, `unsealAesGcmAad` added to `packages/crypto/src/aes/index.ts` and `packages/crypto/src/index.ts`. Implementations stay in the named files (C-02: vitest coverage excludes index barrels).

### `tests/vectors/crypto/node-aad.json` — `seal_vectors` array

One committed entry:
- Key: 32-byte fixed hex (same as aes-gcm.json precedent)
- IV: `000102030405060708090a0b` (sequential 12 bytes)
- Plaintext: `4e6f64654d657461` ("NodeMeta", 8 bytes)
- AAD inputs: canonical UUID, kind=folder, generation=42, role=body
- Ciphertext: `cf6bfe784b825669294884ec63a59327c004cc03571e1227` (24 bytes = 8 plaintext + 16 tag)

Computed by calling `encryptAesGcmAad` (deterministic, fixed IV) — never `sealAesGcmAad` (D-01b: random IV cannot produce a fixed committed vector).

### TS Full-Seal KAT — `packages/crypto/src/__tests__/build-node-aad.test.ts`

Guard `expect(sealVectors.length).toBeGreaterThanOrEqual(1)` before iterating (prevents vacuous pass if array is ever emptied — mirrors the Rust `!seal_vectors.is_empty()` guard in plan 04). Each entry: rebuild AAD via `buildNodeAad`, call `encryptAesGcmAad(plaintext, key, iv, aad)`, assert `bytesToHex(result) === v.ciphertext`. Proves the AAD flows into the AEAD computation, not merely alongside it (T-61-10).

### D-02/CRYPTO-03 Extended Transplant/Negative Suite

Eight tests in a single describe block. First test is "correct-AAD unseal succeeds" — proves all subsequent rejections are AAD-specific, not blanket decryption failures:

| Case | What differs | Expected |
|------|-------------|----------|
| correct AAD | — | succeeds |
| wrong nodeId | different UUID | rejects |
| wrong role | 0x01→0x02 | rejects |
| wrong generation | 42→43 | rejects |
| wrong kind | folder→file | rejects |
| forged domain v2 | byte 21: 0x31→0x32 | rejects |
| flipped auth-tag bit | last byte XOR 0x01 | rejects |
| truncated blob | 27 bytes < 28 | rejects |

## Verification Results

- `pnpm --filter @cipherbox/crypto test`: **196 tests passed** (10 test files, up from 187 after Task 1 GREEN, 196 after Task 2)
- `bash scripts/check-vector-parity.sh`: **exits 0**, all 10 vector files OK including node-aad.json

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Unused import blocked lint-staged in RED commit**

- **Found during:** Task 1 RED commit attempt
- **Issue:** Added `hexToBytes` to the imports for the RED commit (needed in Task 2) — lint-staged ESLint flagged `@typescript-eslint/no-unused-vars`
- **Fix:** Removed `hexToBytes` from the imports in the RED commit; added it back in Task 2 when it was actually used
- **Files modified:** build-node-aad.test.ts

No other deviations. Plan executed as written.

## Known Stubs

None. All functions are fully implemented and exercised by green tests.

## Threat Flags

None. All four threats from the plan's threat model are mitigated:

| Threat | Mitigation |
|--------|-----------|
| T-61-07 AAD transplant | GCM auth tag covers AAD; D-02 suite proves all five wrong-AAD variants reject |
| T-61-08 auth-tag truncation | MIN_SEALED_SIZE (28 bytes) guard; truncated-blob test |
| T-61-09 IV reuse | sealAesGcmAad always calls generateIv(); fresh-IV test asserts two identical inputs differ |
| T-61-10 AAD not threaded into AEAD | Full-seal KAT pins exact ciphertext; only matches if additionalData enters the GCM computation |

## Self-Check: PASSED

Created files confirmed present:
- `packages/crypto/src/aes/encrypt.ts` — contains `encryptAesGcmAad`
- `packages/crypto/src/aes/decrypt.ts` — contains `decryptAesGcmAad`
- `packages/crypto/src/aes/seal.ts` — contains `sealAesGcmAad`/`unsealAesGcmAad`
- `tests/vectors/crypto/node-aad.json` — contains `seal_vectors` array
- `packages/crypto/src/__tests__/build-node-aad.test.ts` — contains full-seal KAT + transplant suite

All commits confirmed in git log: d861146a4, ce1b33b3c, 8e806b3b2.
