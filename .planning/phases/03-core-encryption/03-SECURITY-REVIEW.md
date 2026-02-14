# Security Review: CipherBox Core Encryption (PR #29)

**Review Date:** 2026-01-20
**Reviewer:** Claude Code Security Agent
**Files Analyzed:** 12 source files + 6 test files
**Crypto Operations:** 8 distinct operations

## Executive Summary

**Overall Assessment:** GOOD with MINOR issues

The implementation demonstrates solid cryptographic practices overall. It uses the correct algorithms (AES-256-GCM, ECIES with secp256k1, Ed25519, HKDF-SHA256), properly validates inputs, and uses generic error messages to prevent oracle attacks. The test coverage is comprehensive for the critical paths.

---

## Findings

### [MEDIUM] M1: Missing IV-to-ciphertext binding in AES-GCM API

**Location:** `packages/crypto/src/aes/encrypt.ts:23-65`

**Issue:**
The API requires callers to manage IV separately. While the documentation warns about IV reuse, the API design makes it easy to:

1. Accidentally lose or mismatch the IV
2. Accidentally reuse an IV with the same key
3. Store ciphertext without its IV, making decryption impossible

**Impact:**
If a caller stores ciphertext without the corresponding IV, data is permanently lost. If they reuse an IV with the same key, AES-GCM security completely breaks down (XOR of plaintexts is leaked, authentication is compromised).

**Recommendation:**
Provide a higher-level "seal/unseal" API that handles IV generation and prepends it to ciphertext:

```typescript
export async function sealAesGcm(plaintext: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  const iv = generateIv();
  const ciphertext = await encryptAesGcm(plaintext, key, iv);
  return concatBytes(iv, ciphertext);
}

export async function unsealAesGcm(sealed: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  const iv = sealed.slice(0, AES_IV_SIZE);
  const ciphertext = sealed.slice(AES_IV_SIZE);
  return decryptAesGcm(ciphertext, key, iv);
}
```

---

### [MEDIUM] M2: No validation of ECIES ciphertext minimum length

**Location:** `packages/crypto/src/ecies/decrypt.ts:23-49`

**Issue:**
ECIES ciphertext has a minimum structure: 65 bytes ephemeral public key + 16 bytes auth tag = at least 81 bytes for even 0 bytes of plaintext. Passing a malformed short buffer to `eciesjs` relies entirely on that library's error handling.

**Impact:**
Low - `eciesjs` will throw, which gets caught and converted to a generic error. However, explicit validation is defense-in-depth and provides faster failures.

**Recommendation:**

```typescript
const ECIES_MIN_CIPHERTEXT_SIZE = 65 + 16; // ephemeral pubkey + auth tag

if (wrappedKey.length < ECIES_MIN_CIPHERTEXT_SIZE) {
  throw new CryptoError('Key unwrapping failed', 'KEY_UNWRAPPING_FAILED');
}
```

---

### [MEDIUM] M3: Public key validation insufficient for ECIES wrap

**Location:** `packages/crypto/src/ecies/encrypt.ts:29-37`

**Issue:**
The validation checks length and prefix but does not verify that the point is actually on the secp256k1 curve. A malicious or corrupted public key with the right format could potentially cause issues in the underlying library.

**Impact:**
Low - `eciesjs` should reject invalid curve points. However, explicit validation would catch malformed keys earlier.

**Recommendation:**

```typescript
import { ProjectivePoint } from '@noble/secp256k1';

// After length/prefix checks:
try {
  ProjectivePoint.fromHex(recipientPublicKey);
} catch {
  throw new CryptoError('Key wrapping failed', 'INVALID_PUBLIC_KEY_FORMAT');
}
```

---

### [LOW] L1: Memory clearing has limited effectiveness

**Location:** `packages/crypto/src/utils/memory.ts:1-37`

**Issue:**
The `clearBytes` utility exists but is never actually used in the crypto module's core operations. Keys returned from functions remain in memory longer than necessary.

**Impact:**
Low in browser context (short-lived), but sensitive keys remain in memory longer than necessary.

**Recommendation:**
Document the expected caller responsibility for clearing keys, or use `clearBytes` in error paths.

---

### [LOW] L2: Missing empty ciphertext validation in AES decrypt

**Location:** `packages/crypto/src/aes/decrypt.ts:23-66`

**Issue:**
AES-GCM ciphertext must be at least 16 bytes (the authentication tag). An empty or too-short ciphertext will fail in Web Crypto, but explicit validation provides clearer error handling.

**Recommendation:**

```typescript
if (ciphertext.length < AES_TAG_SIZE) {
  throw new CryptoError('Decryption failed', 'DECRYPTION_FAILED');
}
```

---

### [LOW] L3: Ed25519 keygen duplicates sha512Sync configuration

**Location:**

- `packages/crypto/src/ed25519/keygen.ts:13`
- `packages/crypto/src/ed25519/sign.ts:18`

**Issue:**
The Ed25519 library configuration is duplicated in two files. This could lead to inconsistency if one is updated without the other.

**Recommendation:**
Centralize the Ed25519 configuration in a single shared module.

---

## Positive Security Properties

1. **Correct algorithm choices**: AES-256-GCM, ECIES/secp256k1, Ed25519, HKDF-SHA256
2. **Web Crypto API usage**: Hardware-accelerated, well-audited implementation
3. **Generic error messages**: Prevents oracle attacks across all crypto operations
4. **Input validation**: Key sizes, IV sizes, public key format all validated
5. **Test coverage**: Comprehensive tests including tamper detection and error oracle checks
6. **Ephemeral key randomness**: ECIES produces different ciphertext each call (verified by tests)
7. **Audited libraries**: Uses `@noble/*` and `eciesjs` which are well-reviewed
8. **IPNS signing**: Correctly follows IPFS specification with proper prefix

---

## Test Coverage Assessment

| Category                        | Coverage  | Notes                                       |
| ------------------------------- | --------- | ------------------------------------------- |
| AES-GCM round-trip              | Excellent | Includes empty, large data, error cases     |
| AES-GCM tamper detection        | Excellent | Tests both ciphertext and tag modification  |
| AES-GCM error oracle prevention | Excellent | Verifies all errors are identical           |
| ECIES round-trip                | Excellent | Multiple key sizes, randomness verification |
| ECIES tamper detection          | Good      | Tests middle-byte tampering, truncation     |
| Ed25519 signing                 | Excellent | Empty, large, determinism, wrong key cases  |
| HKDF derivation                 | Excellent | All parameter variations tested             |
| Vault lifecycle                 | Excellent | Multi-cycle, multi-user scenarios           |

---

## Summary

| Severity | Count | Description                                                        |
| -------- | ----- | ------------------------------------------------------------------ |
| Critical | 0     | -                                                                  |
| High     | 0     | -                                                                  |
| Medium   | 3     | IV binding, ECIES length validation, public key curve validation   |
| Low      | 3     | Memory clearing unused, AES min length, Ed25519 config duplication |

### Conclusion

This is a solid cryptographic implementation suitable for a technology demonstrator. The core algorithms are correctly used, input validation is present, and error handling prevents information leakage. The medium-severity issues relate to API design that could be improved for production hardening, but do not represent vulnerabilities in the current implementation if callers follow documented usage patterns.

---

_Review completed: 2026-01-20_
