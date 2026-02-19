# Security Review Report

**Date:** 2026-02-15
**Scope:** PRs #125 (Phase 12.2 — Encrypted Device Registry), #126 (Phase 12.3 — SIWE Wallet Login + Unified Identity), #127 (Phase 12.3.1 — Pre-wipe Identity Cleanup), #128 (Phase 12.4 — MFA + Cross-Device Approval)
**Reviewer:** Claude (security:review command)
**Files Reviewed:** 70+ source files across 4 domains
**Lines of Diff:** ~28,700

## Executive Summary

Phases 12.2-12.4 introduce device identity, wallet-based authentication (SIWE), multi-factor authentication, and cross-device approval flows. The core cryptographic primitives (ECIES, HKDF, Ed25519) are correctly implemented using Web Crypto API and well-audited libraries. However, the new auth/identity linking and device approval flows contain several protocol-level vulnerabilities — most notably a SIWE nonce replay in wallet linking and missing rate limiting on security-critical endpoints. The zero-knowledge property is preserved throughout: the server never sees plaintext keys.

**Risk Level:** HIGH (2 Critical issues require immediate attention before merge)

## Findings Summary

| Severity | Count |
| -------- | ----- |
| Critical | 4     |
| High     | 8     |
| Medium   | 11    |
| Low      | 8     |
| Info     | 5     |

## Files Reviewed

| Domain                  | Key Files                                                                                                | Risk Level |
| ----------------------- | -------------------------------------------------------------------------------------------------------- | ---------- |
| Crypto package          | `packages/crypto/src/registry/*`, `packages/crypto/src/vault/*`                                          | Medium     |
| Auth backend            | `apps/api/src/auth/**`, `apps/api/src/vault/**`                                                          | High       |
| Device approval backend | `apps/api/src/device-approval/**`                                                                        | High       |
| Frontend (web)          | `apps/web/src/hooks/*`, `apps/web/src/stores/*`, `apps/web/src/lib/**`, `apps/web/src/components/mfa/**` | Medium     |
| Frontend (desktop)      | `apps/desktop/src-tauri/src/**`                                                                          | Medium     |

---

## Critical Issues

### C-01: Wallet Linking Does Not Consume SIWE Nonce — Replay Attack

**Severity:** CRITICAL
**Location:** `apps/api/src/auth/auth.service.ts:350-417`
**PR:** #126

The `linkWalletMethod` extracts the nonce from the SIWE message and passes it directly to `verifySiweMessage` as the `expectedNonce`. The nonce is compared against itself — it always passes. Unlike the `walletLogin` flow in `identity.controller.ts` which correctly stores/consumes nonces via Redis, the link flow has:

- No server-side nonce generation
- No Redis nonce consumption
- No replay protection

**Impact:** A captured SIWE message+signature pair can be replayed indefinitely to link a wallet to an attacker's account. No expiration unless the SIWE message itself has an `expirationTime`.

**Recommendation:**

```typescript
// Add Redis nonce consumption before verification
const nonceKey = `siwe:nonce:${parsed.nonce}`;
const nonceDeleted = await this.redis.del(nonceKey);
if (!nonceDeleted) {
  throw new BadRequestException('Invalid or expired nonce');
}
```

---

### C-02: Login Endpoint Accepts Arbitrary `publicKey` Without Cryptographic Binding

**Severity:** CRITICAL
**Location:** `apps/api/src/auth/auth.service.ts:42-128`, `apps/api/src/auth/dto/login.dto.ts:14-21`
**PR:** #126

The JWT is verified but `loginDto.publicKey` is accepted blindly with no validation that it corresponds to the authenticated identity. The JWT `sub` is a UUID, not a public key. An attacker with a valid JWT could submit an arbitrary publicKey. The `Like('pending-core-kit-${verifierId}%')` placeholder resolution on line 61 could be exploited to overwrite a placeholder user's publicKey.

**Mitigating factor:** MPC architecture means client can't derive a private key for an arbitrary public key without controlling Web3Auth shares. However, server has no way to verify this.

**Recommendation:** At minimum, add format validation (`/^04[0-9a-fA-F]{128}$/`). Ideally, require a signed challenge proving possession of the private key.

---

### C-03: Recovery Mnemonic Retained in React State — Never Cleared

**Severity:** CRITICAL
**Location:** `apps/web/src/components/mfa/MfaEnrollmentWizard.tsx:25`
**PR:** #128

The 24-word recovery mnemonic is stored in `useState<string[]>` and never cleared when the wizard completes or when the component unmounts. The mnemonic is equivalent to a factor key and grants full vault access. It persists in the React fiber tree and closures until garbage collection.

**Recommendation:**

```typescript
const handleComplete = useCallback(() => {
  setMnemonic([]);
  onComplete();
}, [onComplete]);

useEffect(() => () => setMnemonic([]), []);
```

---

### C-04: No Rate Limiting on Device Approval Endpoints

**Severity:** CRITICAL
**Location:** `apps/api/src/device-approval/device-approval.controller.ts:27`
**PR:** #128

The device approval controller has only `JwtAuthGuard` — no `ThrottlerGuard`. An attacker with a valid JWT could flood `POST /device-approval/request` with thousands of pending requests, causing approval fatigue on legitimate devices (social engineering via notification spam).

**Recommendation:**

```typescript
@UseGuards(JwtAuthGuard, ThrottlerGuard)
@Controller('device-approval')
// Plus per-endpoint: @Throttle({ default: { ttl: 60000, limit: 3 } }) on createRequest
```

---

## High Priority Issues

### H-01: Race Condition in `unlinkMethod` — TOCTOU

**Severity:** HIGH
**Location:** `apps/api/src/auth/auth.service.ts:423-445`
**PR:** #126

Classic TOCTOU: "count methods, then delete if count > 1". Two concurrent unlink requests when user has exactly 2 methods could both pass the check and delete both methods — leaving the user locked out with zero auth methods.

**Recommendation:** Wrap in transaction with `SELECT ... FOR UPDATE` lock.

---

### H-02: Self-Approval Not Prevented in Device Approval

**Severity:** HIGH
**Location:** `apps/api/src/device-approval/device-approval.service.ts:103-128`
**PR:** #128

No server-side check that `dto.respondedByDeviceId !== approval.deviceId`. A device could approve its own request. The `respondedByDeviceId` is entirely self-reported and unauthenticated.

**Recommendation:** Add `if (dto.respondedByDeviceId === approval.deviceId) throw BadRequestException`.

---

### H-03: Approval Accepts Null `encryptedFactorKey`

**Severity:** HIGH
**Location:** `apps/api/src/device-approval/device-approval.service.ts:122-123`
**PR:** #128

The service uses `dto.encryptedFactorKey ?? null`. If DTO validation is bypassed, an "approve" action stores a null key. The requester sees "approved" but has no factor key — stuck state.

**Recommendation:** Add explicit null check in service layer as defense-in-depth.

---

### H-04: Ephemeral Public Key Not Validated for Length/Format

**Severity:** HIGH
**Location:** `apps/api/src/device-approval/dto/create-approval.dto.ts:22-28`
**PR:** #128

Only `@IsHexadecimal()` — no length check (should be 130 hex chars for uncompressed secp256k1), no `04` prefix check. Attackers can create "trap" approval requests with invalid keys that always fail to approve, wasting user effort.

**Recommendation:** Add `@Length(130, 130)` and prefix validation.

---

### H-05: No Rate Limiting on `/auth/login` Endpoint

**Severity:** HIGH
**Location:** `apps/api/src/auth/auth.controller.ts:49-82`
**PR:** #126

Unlike identity endpoints which have `@UseGuards(ThrottlerGuard)`, the main login endpoint has no rate limiting. The global ThrottlerModule is not auto-applied (requires explicit guard per endpoint).

**Recommendation:** Add `@UseGuards(ThrottlerGuard)` and `@Throttle()`.

---

### H-06: No Memory Clearing of Sensitive Key Material

**Severity:** HIGH
**Location:** `packages/crypto/src/registry/encrypt.ts:49-62`, `packages/crypto/src/vault/init.ts:39-54`
**PR:** #125, #127

Decrypted registry plaintext, encrypted JSON buffers, and HKDF-derived seeds are never cleared from memory. The project exports `clearBytes` but doesn't use it in these hot paths.

**Recommendation:** Add `try/finally` blocks with `clearBytes(plaintext)` in `encryptRegistry` and `decryptRegistry`.

---

### H-07: Schema Validation Does Not Restrict String Field Lengths

**Severity:** HIGH
**Location:** `packages/crypto/src/registry/schema.ts:69-84`
**PR:** #125

Fields like `deviceId`, `publicKey`, `ipHash` are only checked as strings, not for length/format. A compromised device could inject multi-megabyte strings causing memory exhaustion on other devices.

**Recommendation:** Validate `deviceId`/`publicKey`/`ipHash` as 64-char hex. Add max length on `name`, `appVersion`, `deviceModel`.

---

### H-08: Device Ed25519 Private Key Stored in IndexedDB Without Encryption

**Severity:** HIGH
**Location:** `apps/web/src/lib/device/identity.ts:86-92`
**PR:** #125

The device Ed25519 private key is stored as a plaintext number array in IndexedDB. XSS can exfiltrate it, enabling device impersonation in the registry and potentially unauthorized device approval in the MFA flow.

**Recommendation:** Use non-extractable `CryptoKey` objects or wrap with a session-derived key.

---

### H-09: `getLinkedMethods` May Leak Hashed Identifiers

**Severity:** HIGH
**Location:** `apps/api/src/auth/auth.service.ts:245-258`
**PR:** #126

When `identifierDisplay` is null, the raw SHA-256 hash is returned as the "identifier" to the client. This leaks internal hashed identifiers and could appear as the user's email in refresh token responses.

**Recommendation:** Fall back to `'[redacted]'` instead of the raw hash.

---

## Medium Priority Issues

### M-01: No Unique Constraint on `(type, identifier_hash)` in `auth_methods`

**Location:** `apps/api/src/migrations/1700000000000-FullSchema.ts:66-90` | **PR:** #126

Only an index (not unique constraint). Concurrent `linkMethod` requests for the same identifier can bypass the application-level duplicate check, creating duplicate auth methods.

### M-02: `findOrCreateUserByIdentifier` Race Condition

**Location:** `apps/api/src/auth/controllers/identity.controller.ts:266-307` | **PR:** #126

Two concurrent first-login requests for the same identity can both create new users. Related to M-01.

### M-03: `LinkMethodDto` Missing Validation Parity with `WalletVerifyDto`

**Location:** `apps/api/src/auth/dto/link-method.dto.ts:28-38` | **PR:** #126

No `@MaxLength(2048)` on `siweMessage`, no signature format regex. Allows arbitrarily large payloads.

### M-04: No Limit on Concurrent Pending Approval Requests Per User

**Location:** `apps/api/src/device-approval/device-approval.service.ts:22-33` | **PR:** #128

Unlimited pending requests can be created, filling the DB table and overwhelming the approver UI.

### M-05: No Expired Request Cleanup / Garbage Collection

**Location:** `apps/api/src/device-approval/device-approval.service.ts` | **PR:** #128

Expired requests (including encrypted factor keys) persist in DB indefinitely. Only lazily expired on poll.

### M-06: `deviceName` Has No Max Length or Character Restriction

**Location:** `apps/api/src/device-approval/dto/create-approval.dto.ts:13-19` | **PR:** #128

User-controlled, displayed in approval modal. Could contain social engineering text or be megabytes long.

### M-07: Temporary REQUIRED_SHARE JWT Has Full Scope

**Location:** `apps/web/src/hooks/useAuth.ts:253-258` | **PR:** #128

Placeholder `pending-core-kit-{userId}` login gets a full-privilege JWT. Should be scoped to device-approval endpoints only.

### M-08: HKDF Salt Reuse Across Vault and Registry Derivation

**Location:** `packages/crypto/src/registry/derive-ipns.ts:24`, `packages/crypto/src/vault/derive-ipns.ts:28` | **PR:** #125, #127

Both use `CipherBox-v1` salt. Domain separation relies solely on `info` parameter. Technically correct per RFC 5869 but lacks defense-in-depth.

### M-09: `sequenceNumber` Allows Overflow Past `MAX_SAFE_INTEGER`

**Location:** `packages/crypto/src/registry/schema.ts:38-44` | **PR:** #125

JSON.parse silently loses precision beyond 2^53-1, enabling sequence number manipulation.

### M-10: No Max Device Count in Registry Schema Validation

**Location:** `packages/crypto/src/registry/schema.ts:47-54` | **PR:** #125

A compromised device can bloat the registry with millions of entries, causing DoS on other devices.

### M-11: Rust Debug Derives on Sensitive Token Structs

**Location:** `apps/desktop/src-tauri/src/api/types.rs:8-38` | **PR:** #127

All auth structs derive `Debug`. Any `{:?}` format outputs full tokens to logs. Future `log::debug!` calls would leak secrets.

---

## Low Priority Issues

| ID   | Issue                                                                         | Location                                                       | PR   |
| ---- | ----------------------------------------------------------------------------- | -------------------------------------------------------------- | ---- |
| L-01 | Schema allows `status: 'authorized'` with non-null `revokedAt/revokedBy`      | `packages/crypto/src/registry/schema.ts:86-107`                | #125 |
| L-02 | Timestamps not validated for reasonable ranges                                | `packages/crypto/src/registry/schema.ts:97-99`                 | #125 |
| L-03 | Schema allows extra properties (no strict mode / prototype pollution defense) | `packages/crypto/src/registry/schema.ts:25-57`                 | #125 |
| L-04 | Placeholder `publicKey` uses predictable userId in pattern                    | `apps/api/src/auth/controllers/identity.controller.ts:288-294` | #126 |
| L-05 | Email logged in OTP service in production                                     | `apps/api/src/auth/services/email-otp.service.ts:102`          | #126 |
| L-06 | IP hash uses unsalted SHA-256 (trivially reversible for IPv4)                 | `apps/web/src/lib/device/info.ts:113-117`                      | #125 |
| L-07 | `ipHash` hardcoded to empty string (feature non-functional)                   | `apps/web/src/hooks/useAuth.ts:150`                            | #125 |
| L-08 | Incomplete store clearing on API client refresh failure                       | `apps/web/src/lib/api/client.ts:58-63`                         | #128 |

---

## Informational (Positive Observations)

1. **ECIES implementation is correct**: Public key validation (size, format, curve point), generic error messages prevent oracle attacks, ephemeral key generation ensures different ciphertext each time.

2. **SIWE nonce lifecycle correct on wallet login path**: Nonces generated with `randomBytes(16)`, stored in Redis with 5-min TTL, atomically consumed before verification.

3. **Refresh token security is solid**: Argon2 hashing, rotation on use, HTTP-only cookies, 7-day expiry, prefix-based lookup.

4. **Zero-knowledge property preserved**: Vault keys encrypted client-side, server never sees plaintext. ECIES for key transport. Factor keys transferred only via ECIES. Recovery phrase never sent to server.

5. **Key zeroing on logout implemented**: Both web (`Uint8Array.fill(0)`) and desktop (`zeroize` crate) properly zero key material on logout/state clear.

---

## Compliance Checklist

| Rule                                         | Status  | Notes                                                                                  |
| -------------------------------------------- | ------- | -------------------------------------------------------------------------------------- |
| No privateKey in localStorage/sessionStorage | PARTIAL | Device Ed25519 key in IndexedDB unencrypted (H-08). Vault keys are memory-only.        |
| No sensitive keys logged                     | PARTIAL | TSS pubkey coordinates logged on anomaly. Rust Debug derives could leak tokens (M-11). |
| No unencrypted keys sent to server           | PASS    | All key material ECIES-encrypted before transmission.                                  |
| ECIES used for key wrapping                  | PASS    | Correct usage via `eciesjs` library.                                                   |
| AES-256-GCM for content encryption           | PASS    | Used in ECIES envelope (via library) and file encryption.                              |
| Server zero-knowledge of plaintext           | PASS    | Server never decrypts keys or content.                                                 |
| IPNS keys encrypted with TEE public key      | PASS    | Unchanged from prior phases.                                                           |

---

## Recommendations Summary (Priority Order)

| Priority | Recommendation                                                | Effort | Fix In                        |
| -------- | ------------------------------------------------------------- | ------ | ----------------------------- |
| P0       | **C-01**: Add Redis nonce consumption to `linkWalletMethod`   | LOW    | auth.service.ts               |
| P0       | **C-02**: Add publicKey format validation in LoginDto         | LOW    | login.dto.ts                  |
| P0       | **C-04**: Add ThrottlerGuard to device-approval controller    | LOW    | device-approval.controller.ts |
| P0       | **C-03**: Clear mnemonic on wizard completion/unmount         | LOW    | MfaEnrollmentWizard.tsx       |
| P1       | **H-01**: Wrap `unlinkMethod` in DB transaction with row lock | MEDIUM | auth.service.ts               |
| P1       | **H-02**: Prevent self-approval in device approval service    | LOW    | device-approval.service.ts    |
| P1       | **H-03**: Add null check for encryptedFactorKey on approve    | LOW    | device-approval.service.ts    |
| P1       | **H-04**: Add `@Length(130)` on ephemeralPublicKey DTO        | LOW    | create-approval.dto.ts        |
| P1       | **H-05**: Add ThrottlerGuard to `/auth/login`                 | LOW    | auth.controller.ts            |
| P1       | **H-06**: Add clearBytes() in encrypt/decrypt finally blocks  | LOW    | encrypt.ts                    |
| P1       | **H-07**: Add length/format validation to registry schema     | MEDIUM | schema.ts                     |
| P1       | **H-09**: Fall back to '[redacted]' not raw hash              | LOW    | auth.service.ts               |
| P2       | **M-01**: Add UNIQUE constraint on (type, identifier_hash)    | MEDIUM | migration                     |
| P2       | **M-04**: Add concurrent pending request limit (max 5)        | LOW    | device-approval.service.ts    |
| P2       | **M-06**: Add @MaxLength(100) on deviceName                   | LOW    | create-approval.dto.ts        |
| P2       | **M-03**: Mirror WalletVerifyDto validation to LinkMethodDto  | LOW    | link-method.dto.ts            |
| P2       | **M-11**: Replace #[derive(Debug)] with redacting impl        | MEDIUM | types.rs                      |
| P3       | **H-08**: Encrypt device key in IndexedDB or use CryptoKey    | HIGH   | identity.ts                   |
| P3       | **M-07**: Scope REQUIRED_SHARE JWT to approval endpoints only | HIGH   | auth flow                     |

---

## Next Steps

1. **Immediate (before merge of PR #128):** Fix C-01, C-03, C-04, H-02, H-03, H-04, H-05 — all LOW effort
2. **Short-term (next sprint):** Fix H-01, H-06, H-07, M-01, M-04, M-06
3. **Medium-term:** H-08 (IndexedDB encryption), M-07 (scoped JWT), M-11 (Rust debug redaction)

---

_Generated by security:review command_
_This review is automated guidance, not a substitute for professional security audit_
