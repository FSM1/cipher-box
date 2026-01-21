# Security Review - LOW Severity Issues Backlog

**Date:** 2026-01-21
**Source:** Phase 5 Security Review (REVIEW-2026-01-21-phase5.md)
**Status:** Deferred for future work

These issues were identified during the Phase 5 security review but have low severity
and are deferred for future implementation.

---

## 1. Value parameter not validated in create-record.ts

**Location:** `packages/crypto/src/ipns/create-record.ts:25-26`

**Issue:** The `value` parameter is documented to be an IPFS path but is not validated.
The underlying `ipns` library may perform validation, but early validation would
provide clearer error messages.

**Suggested Fix:**

```typescript
// Validate value is a valid IPFS path
if (!value || typeof value !== 'string' || !value.startsWith('/ipfs/')) {
  throw new CryptoError('Invalid IPFS path value', 'SIGNING_FAILED');
}
```

---

## 2. Missing input validation in unmarshalIpnsRecord

**Location:** `packages/crypto/src/ipns/marshal.ts:35-37`

**Issue:** No validation is performed on the input `bytes` before passing to
`ipnsUnmarshal`. A null/undefined check would provide clearer error messages.

**Suggested Fix:**

```typescript
export function unmarshalIpnsRecord(bytes: Uint8Array): IPNSRecord {
  if (!bytes || bytes.length === 0) {
    throw new Error('Invalid IPNS record bytes: empty or undefined');
  }
  return ipnsUnmarshal(bytes);
}
```

---

## 3. Missing lifetime validation in create-record.ts

**Location:** `packages/crypto/src/ipns/create-record.ts:35`

**Issue:** No validation that `lifetimeMs` is positive or within reasonable bounds.
Zero or negative lifetime would create immediately-expired records.

**Suggested Fix:**

```typescript
// Validate lifetime
if (lifetimeMs <= 0 || lifetimeMs > 365 * 24 * 60 * 60 * 1000) {
  // Max 1 year
  throw new CryptoError('Invalid lifetime value', 'SIGNING_FAILED');
}
```

---

## 4. Incorrect error code in derive-name.ts

**Location:** `packages/crypto/src/ipns/derive-name.ts:46`

**Issue:** The error code `SIGNING_FAILED` is incorrect for a name derivation
operation (which involves no signing). This could confuse error handling.

**Suggested Fix:**
Add a new error code `KEY_DERIVATION_FAILED` to `types.ts` and use it:

```typescript
throw new CryptoError('IPNS name derivation failed', 'KEY_DERIVATION_FAILED');
```

---

## 5. Sensitive key copies not cleared in AES encrypt

**Location:** `packages/crypto/src/aes/encrypt.ts:40-42`

**Issue:** Copies of the key are created for Web Crypto API but never zeroed after
use. While JavaScript GC makes this difficult to exploit, it's a defense-in-depth
concern.

**Suggested Fix:**

```typescript
try {
  // ... existing crypto code ...
  return new Uint8Array(ciphertext);
} finally {
  // Zero sensitive data (best-effort)
  new Uint8Array(keyBuffer).fill(0);
}
```

**Note:** This is difficult to guarantee in JavaScript due to GC behavior.

---

## 6. IV hex string not length-validated in metadata.ts

**Location:** `packages/crypto/src/folder/metadata.ts:52`

**Issue:** The IV is converted from hex but not immediately validated for correct
length (12 bytes / 24 hex chars). Error occurs deeper in call stack.

**Suggested Fix:**

```typescript
const iv = hexToBytes(encrypted.iv);
if (iv.length !== 12) {
  throw new CryptoError('Invalid IV size', 'INVALID_IV_SIZE');
}
```

---

## 7. Fire-and-forget unpinning could leave orphaned data

**Location:** `apps/web/src/services/folder.service.ts:305-306`

**Issue:** Unpin operations are fire-and-forget with swallowed errors. If unpinning
fails, encrypted file blobs remain pinned and count against user quota.

**Suggested Fix:**
Track failed unpins for retry, or log for debugging:

```typescript
Promise.all(
  cidsToUnpin.map((cid) =>
    params.unpinCid(cid).catch((err) => {
      console.warn(`Failed to unpin ${cid}:`, err);
      // TODO: Add to retry queue or track for cleanup
    })
  )
);
```

---

## Priority Notes

These issues are LOW severity because:

- They don't expose security vulnerabilities directly
- The primary crypto operations are correct and secure
- Impact is limited to edge cases or developer experience
- The underlying libraries often provide their own validation

Consider addressing these when:

- Doing code cleanup/refactoring
- Adding comprehensive test coverage
- Implementing error handling improvements
- Preparing for production hardening

---

_Generated from security:review command - Phase 5_
