# Security Review Report

**Date:** 2026-01-21
**Scope:** Phase 5 - Folder System
**Reviewer:** Claude (security:review command)
**Status:** REMEDIATED (2026-01-21)
**Verification Pass:** 2026-01-21 (PR review)

## Executive Summary

Phase 5 implements a cryptographic folder hierarchy with IPNS-based metadata publishing. The cryptographic implementation is **sound** — AES-256-GCM is correctly used with proper IV generation, ECIES key wrapping is properly implemented, and the zero-knowledge architecture is maintained.

**All CRITICAL, HIGH, and MEDIUM issues have been fixed.**

~~**Risk Level:** HIGH (due to incomplete logout security)~~
**Risk Level:** LOW (after remediation)

### Remediation Summary

| Severity | Original | Fixed        |
| -------- | -------- | ------------ |
| CRITICAL | 1        | 1            |
| HIGH     | 3        | 3            |
| MEDIUM   | 8        | 8            |
| LOW      | 7        | 0 (deferred) |

**LOW severity issues documented in:** `.planning/security/LOW-SEVERITY-BACKLOG.md`

## Files Reviewed

| File                                      | Crypto Operations                    | Risk Level |
| ----------------------------------------- | ------------------------------------ | ---------- |
| packages/crypto/src/ipns/create-record.ts | IPNS record creation, key conversion | MEDIUM     |
| packages/crypto/src/ipns/derive-name.ts   | IPNS name derivation                 | LOW        |
| packages/crypto/src/ipns/marshal.ts       | Record serialization                 | LOW        |
| packages/crypto/src/folder/metadata.ts    | AES-GCM encrypt/decrypt              | MEDIUM     |
| apps/api/src/ipns/ipns.service.ts         | Record relay, key storage            | HIGH       |
| apps/api/src/ipns/ipns.controller.ts      | Auth, input validation               | CRITICAL   |
| apps/web/src/stores/vault.store.ts        | Key management                       | HIGH       |
| apps/web/src/stores/folder.store.ts       | Folder key management                | HIGH       |
| apps/web/src/services/folder.service.ts   | Folder operations                    | MEDIUM     |
| apps/web/src/hooks/useFolder.ts           | UI integration                       | MEDIUM     |
| apps/web/src/hooks/useAuth.ts             | Logout flow                          | HIGH       |

## Findings Summary

| Severity | Count | Description                                    |
| -------- | ----- | ---------------------------------------------- |
| CRITICAL | 1     | Missing ValidationPipe in API                  |
| HIGH     | 3     | Incomplete logout, no rate limiting            |
| MEDIUM   | 8     | Input validation, memory clearing, type safety |
| LOW      | 7     | Error messages, logging, minor validation      |

---

## Critical Issues

### 1. [CRITICAL] Missing Global ValidationPipe in API - **FIXED**

**Location:** `apps/api/src/main.ts:7-8`

**Description:** The NestJS application does not configure a global `ValidationPipe`. All DTO decorators (`@IsString()`, `@IsNotEmpty()`, `@Matches()`, etc.) in `PublishIpnsDto` are **not enforced**.

**Impact:** All input validation is bypassed. Attackers can:

- Submit non-string values
- Bypass the `@Matches(/^k51/)` IPNS name validation
- Submit invalid base64 for records

**Fix Applied:**

```typescript
// main.ts
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // [SECURITY: CRITICAL-01] Enable global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    })
  );
  // ...
}
```

---

## High Priority Issues

### 2. [HIGH] Incomplete Logout - Vault and Folder Keys Not Cleared - **FIXED**

**Location:** `apps/web/src/hooks/useAuth.ts:158-189`

**Description:** The logout function calls `clearAuthState()` but does NOT call:

- `useVaultStore.getState().clearVaultKeys()`
- `useFolderStore.getState().clearFolders()`

**Impact:** After logout, all decrypted cryptographic keys remain in memory:

- `rootFolderKey` (AES-256)
- `rootIpnsKeypair.privateKey` (Ed25519)
- All folder keys and IPNS private keys

If XSS occurs after logout, an attacker could extract these keys via `useVaultStore.getState()`.

**Fix Applied:**

```typescript
// [SECURITY: HIGH-02] Clear vault and folder stores BEFORE auth state
useFolderStore.getState().clearFolders();
useVaultStore.getState().clearVaultKeys();
clearAuthState();
```

### 3. [HIGH] Token Refresh Failure Does Not Clear Crypto State - **FIXED**

**Location:** `apps/web/src/lib/api/client.ts:60`

**Description:** When token refresh fails, `useAuthStore.getState().logout()` is called but vault/folder stores are not cleared.

**Fix Applied:**

```typescript
// [SECURITY: HIGH-03] Clear all stores including crypto keys on token refresh failure
useFolderStore.getState().clearFolders();
useVaultStore.getState().clearVaultKeys();
useAuthStore.getState().logout();
```

### 4. [HIGH] No Rate Limiting on IPNS Publish Endpoint - **FIXED**

**Location:** `apps/api/src/ipns/ipns.controller.ts:20`

**Description:** The `/ipns/publish` endpoint has no rate limiting. Each request makes external HTTP calls to `delegated-ipfs.dev` and database writes.

**Impact:**

- Resource exhaustion attacks
- Abuse of delegated routing service
- Potential IP blocking from third-party services

**Fix Applied:**

- Added `@nestjs/throttler` package
- Configured `ThrottlerModule` in `app.module.ts` with global limits
- Added `@Throttle({ default: { limit: 10, ttl: 60000 } })` to publish endpoint

---

## Medium Priority Issues

### 5. [MEDIUM] Private Key Not Cleared After Use in create-record.ts - **FIXED**

**Location:** `packages/crypto/src/ipns/create-record.ts:46-51`

**Description:** The `libp2pKeyBytes` array containing private key material is not zeroed after conversion.

**Fix Applied:** Added `libp2pKeyBytes.fill(0)` immediately after conversion, with error handling to ensure clearing even on exceptions.

### 6. [MEDIUM] Sequence Number Not Validated - **FIXED**

**Location:** `packages/crypto/src/ipns/create-record.ts:31-35`

**Description:** No validation that `sequenceNumber` is non-negative.

**Fix Applied:** Added validation: `if (sequenceNumber < 0n) throw CryptoError(...)`

### 7. [MEDIUM] Unsafe Type Casting After JSON Parse - **FIXED**

**Location:** `packages/crypto/src/folder/metadata.ts:59`

**Description:** Decrypted JSON is cast to `FolderMetadata` without runtime validation.

**Fix Applied:** Added `validateFolderMetadata()` function that validates version, children array, and child entry types.

### 8. [MEDIUM] Large Data Base64 Encoding May Crash - **FIXED**

**Location:** `packages/crypto/src/folder/metadata.ts:35`

**Description:** `btoa(String.fromCharCode(...ciphertext))` may hit argument limits for large folders.

**Fix Applied:** Replaced with `uint8ArrayToBase64()` helper using chunked encoding (32KB chunks).

### 9. [MEDIUM] Insufficient Validation of encryptedIpnsPrivateKey - **FIXED**

**Location:** `apps/api/src/ipns/dto/publish.dto.ts:36-39`

**Description:** Only `@IsString()` validation; no hex format or length validation.

**Fix Applied:** Added `@Matches(/^[0-9a-fA-F]+$/)`, `@MinLength(100)`, `@MaxLength(1000)`.

### 10. [MEDIUM] No Length Validation on metadataCid - **FIXED**

**Location:** `apps/api/src/ipns/dto/publish.dto.ts:23-29`

**Description:** CID format not validated.

**Fix Applied:** Added `@Matches(/^(bafy|bafk|Qm)[a-zA-Z0-9]+$/)`, `@MaxLength(100)`.

### 11. [MEDIUM] Error Messages May Leak Internal Details - **FIXED**

**Location:** `apps/api/src/ipns/ipns.service.ts:118-121`

**Description:** Delegated routing errors passed directly to client.

**Fix Applied:** Log full errors server-side, return generic messages to client.

### 12. [MEDIUM] ipnsName Validation Too Permissive - **FIXED**

**Location:** `apps/api/src/ipns/dto/publish.dto.ts:11`

**Description:** Regex `/^k51/` allows any suffix. Should validate full CIDv1 format.

**Fix Applied:** Changed to `@Matches(/^k51qzi5uqu5[a-z0-9]{40,60}$/)`, `@MaxLength(70)`.

---

## Low Priority / Recommendations - **DEFERRED**

These issues are documented in `.planning/security/LOW-SEVERITY-BACKLOG.md` for future work:

1. **[LOW]** Value parameter not validated in `create-record.ts`
2. **[LOW]** Missing input validation in `unmarshalIpnsRecord`
3. **[LOW]** Missing lifetime validation in `create-record.ts`
4. **[LOW]** Incorrect error code (`SIGNING_FAILED`) in `derive-name.ts:46`
5. **[LOW]** Sensitive key copies not cleared in AES encrypt (`aes/encrypt.ts:40-42`)
6. **[LOW]** IV hex string not length-validated in `metadata.ts:52`
7. **[LOW]** Fire-and-forget unpinning could leave orphaned data

---

## Positive Security Observations

### Cryptographic Correctness

1. **AES-256-GCM Used Correctly:**
   - 12-byte IV (optimal for GCM)
   - 32-byte key size enforced
   - Authentication tag automatically included/verified
   - Web Crypto API provides side-channel resistance

2. **ECIES Key Wrapping:**
   - All folder keys and IPNS private keys are ECIES-wrapped client-side
   - Server never receives plaintext keys

3. **Zero-Knowledge Architecture:**
   - Server only sees encrypted blobs
   - Pre-signed IPNS records (server cannot forge)
   - TEE keys are ECIES-encrypted for TEE only

4. **Secure Random Generation:**
   - Uses `crypto.getRandomValues()` (CSPRNG)
   - Fresh IV per encryption operation

5. **Generic Error Messages:**
   - Crypto errors don't leak information that could enable oracle attacks

### Implementation Safety

6. **Uint8Array for Binary Data:**
   - No string-based key handling in crypto code

7. **Authentication Guards:**
   - JWT guard applied at controller level
   - User scoping on all database queries

8. **Memory Clearing Implemented:**
   - `clearVaultKeys()` and `clearFolders()` zero-fill keys
   - Documented limitation that JavaScript cannot guarantee clearing

---

## Compliance Checklist

Based on project security rules (from CLAUDE.md):

| Rule                                         | Status | Notes                                |
| -------------------------------------------- | ------ | ------------------------------------ |
| No privateKey in localStorage/sessionStorage | PASS   | Keys stored in Zustand (memory-only) |
| No sensitive keys logged                     | PASS   | No key logging found                 |
| No unencrypted keys sent to server           | PASS   | All keys ECIES-wrapped               |
| ECIES used for key wrapping                  | PASS   | Correct implementation               |
| AES-256-GCM used for content encryption      | PASS   | With proper IV generation            |
| Server has zero knowledge of plaintext       | PASS   | Architecture correct                 |
| IPNS keys encrypted with TEE public key      | PASS   | `encryptedIpnsPrivateKey` field      |

**FAILED:**
| Rule | Status | Notes |
|------|--------|-------|
| Keys cleared on logout | FAIL | Vault/folder stores not cleared |

---

## Recommendations Summary

| Priority | Recommendation                                     | Effort | Files                                            |
| -------- | -------------------------------------------------- | ------ | ------------------------------------------------ |
| P0       | Add ValidationPipe to API main.ts                  | LOW    | apps/api/src/main.ts                             |
| P0       | Clear vault/folder stores on logout                | LOW    | apps/web/src/hooks/useAuth.ts, lib/api/client.ts |
| P1       | Add rate limiting to IPNS endpoint                 | MEDIUM | apps/api/src/ipns/ipns.controller.ts             |
| P1       | Strengthen DTO validation                          | LOW    | apps/api/src/ipns/dto/publish.dto.ts             |
| P2       | Clear intermediate key material                    | LOW    | packages/crypto/src/ipns/create-record.ts        |
| P2       | Add runtime type validation for decrypted metadata | LOW    | packages/crypto/src/folder/metadata.ts           |
| P2       | Sanitize error messages                            | LOW    | apps/api/src/ipns/ipns.service.ts                |

---

## Test Cases

### Unit Tests Suggested

```typescript
// packages/crypto/src/ipns/__tests__/security.test.ts
describe('IPNS Security Tests', () => {
  it('should reject private key of wrong size');
  it('should handle sequence number 0');
  it('should reject negative sequence numbers');
  it('should derive consistent IPNS name');
  it('should produce k51... format name');
});

// packages/crypto/src/folder/__tests__/metadata.security.test.ts
describe('Folder Metadata Security Tests', () => {
  it('should detect tampered ciphertext (auth tag verification)');
  it('should detect tampered IV');
  it('should reject decryption with wrong key');
  it('should produce different ciphertext for same plaintext (unique IV)');
  it('should handle large folder metadata');
});

// apps/web/src/stores/__tests__/logout-security.test.ts
describe('Logout Security', () => {
  it('should zero-fill vault keys on clearVaultKeys');
  it('should zero-fill all folder keys on clearFolders');
  it('SECURITY: logout should clear ALL stores');
});

// apps/api/src/ipns/__tests__/ipns.security.test.ts
describe('IPNS API Security Tests', () => {
  it('should reject requests without JWT token');
  it('should reject invalid ipnsName format');
  it('should reject non-base64 record');
  it('should not leak internal error details');
});
```

### Integration Tests Suggested

- [ ] Full logout flow clears all crypto state
- [ ] Token refresh failure clears all crypto state
- [ ] Rate limiting prevents abuse of publish endpoint
- [ ] Invalid DTOs rejected before processing

### Attack Scenarios to Test

- [ ] **XSS after logout** — Verify no keys accessible via store getState()
- [ ] **Input validation bypass** — Confirm ValidationPipe enforced
- [ ] **Rate limit abuse** — Verify throttling works under load

---

## Next Steps

1. **Immediate (P0):**
   - Add `ValidationPipe` to `apps/api/src/main.ts`
   - Fix logout in `apps/web/src/hooks/useAuth.ts` to clear all stores
   - Fix logout in `apps/web/src/lib/api/client.ts` (token refresh failure)

2. **Short-term (P1):**
   - Add `@nestjs/throttler` rate limiting
   - Strengthen DTO validation patterns

3. **Long-term:**
   - Implement test suite from suggested test cases
   - Consider defense-in-depth for key material clearing
   - Document security limitations in user-facing docs

---

## Verification Pass (2026-01-21)

A second security review was conducted to verify all fixes and check for new issues introduced in the PR.

### Verification Results

**All CRITICAL, HIGH, and MEDIUM issues confirmed fixed.**

| Issue                                 | Verification Status                                                             |
| ------------------------------------- | ------------------------------------------------------------------------------- |
| CRITICAL-01: ValidationPipe           | VERIFIED - Correctly configured with whitelist, forbidNonWhitelisted, transform |
| HIGH-02: Logout Key Clearing          | VERIFIED - clearFolders() and clearVaultKeys() called before clearAuthState()   |
| HIGH-03: Token Refresh Key Clearing   | VERIFIED - Clears all crypto stores before logout on refresh failure            |
| HIGH-04: Rate Limiting                | VERIFIED - ThrottlerModule + @Throttle decorator on publish endpoint            |
| MEDIUM-05: Private Key Clearing       | VERIFIED - libp2pKeyBytes.fill(0) with error handling                           |
| MEDIUM-06: Sequence Number Validation | VERIFIED - Rejects negative values with CryptoError                             |
| MEDIUM-07: Unsafe Type Casting        | VERIFIED - validateFolderMetadata() validates structure                         |
| MEDIUM-08: Large Data Base64          | VERIFIED - uint8ArrayToBase64() uses 32KB chunks                                |
| MEDIUM-09: encryptedIpnsPrivateKey    | VERIFIED - Hex format, MinLength(100), MaxLength(1000)                          |
| MEDIUM-10: metadataCid                | VERIFIED - CID format regex, MaxLength(100)                                     |
| MEDIUM-11: Error Message Sanitization | VERIFIED - Generic BAD_GATEWAY messages to client                               |
| MEDIUM-12: ipnsName Validation        | VERIFIED - Strict k51 CIDv1 regex with MaxLength(70)                            |

### New Issues Identified (All LOW Severity)

| Issue                             | Location                                       | Description                                           | Impact                                           |
| --------------------------------- | ---------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------ |
| Missing @Min on keyEpoch          | `apps/api/src/ipns/dto/publish.dto.ts:75-77`   | Accepts negative values                               | Semantically invalid but no security risk        |
| Record MaxLength generous         | `apps/api/src/ipns/dto/publish.dto.ts:34`      | 10KB generous for IPNS (~500 bytes typical)           | Could tighten to 2KB                             |
| btoa() spread in ipns.service     | `apps/web/src/services/ipns.service.ts:45`     | Could hit argument limits for large records           | IPNS records are small, unlikely issue           |
| Incomplete FolderEntry validation | `packages/crypto/src/folder/metadata.ts:49-59` | Only validates type/id/name, not cid/fileKeyEncrypted | Defense-in-depth only, data is authenticated     |
| No weak key detection             | `packages/crypto/src/ipns/create-record.ts:53` | Doesn't reject all-zeros key                          | User would need to deliberately provide weak key |

These LOW severity issues have been added to `LOW-SEVERITY-BACKLOG.md` for future consideration.

### Test Coverage Gaps

| Scenario                                    | Status         | Recommendation                             |
| ------------------------------------------- | -------------- | ------------------------------------------ |
| Token refresh failure clearing crypto state | NOT TESTED     | Add integration test for axios interceptor |
| Rate limiting behavior                      | WEAK ASSERTION | Strengthen test to verify 429 responses    |

### Compliance Checklist (Re-verified)

| Rule                                         | Status |
| -------------------------------------------- | ------ |
| No privateKey in localStorage/sessionStorage | PASS   |
| No sensitive keys logged                     | PASS   |
| No unencrypted keys sent to server           | PASS   |
| ECIES used for key wrapping                  | PASS   |
| AES-256-GCM used for content encryption      | PASS   |
| Server has zero knowledge of plaintext       | PASS   |
| IPNS keys encrypted with TEE public key      | PASS   |
| Keys cleared on logout                       | PASS   |

**Overall Risk Level: LOW**

All security-critical issues have been properly remediated. The implementation correctly follows cryptographic best practices and maintains the zero-knowledge architecture.

---

_Generated by security:review command_
_This review is automated guidance, not a substitute for professional security audit_
