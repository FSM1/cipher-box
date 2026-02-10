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

---

## 8. Missing @Min validation on keyEpoch

**Location:** `apps/api/src/ipns/dto/publish.dto.ts:75-77`
**Added:** 2026-01-21 (Verification Pass)

**Issue:** The `keyEpoch` field accepts any number, including negative values.
While business logic may handle this gracefully, explicit validation would be more defensive.

**Suggested Fix:**

```typescript
@IsNumber()
@IsOptional()
@Min(0, { message: 'keyEpoch must be a non-negative integer' })
@IsInt({ message: 'keyEpoch must be an integer' })
keyEpoch?: number;
```

---

## 9. Record MaxLength could be more restrictive

**Location:** `apps/api/src/ipns/dto/publish.dto.ts:34`
**Added:** 2026-01-21 (Verification Pass)

**Issue:** 10KB (`@MaxLength(10000)`) is generous for IPNS records. Typical signed
IPNS records are ~300-500 bytes when base64 encoded. A lower limit would provide
better protection against abuse.

**Suggested Fix:** Reduce to `@MaxLength(2000)` for tighter validation.

---

## 10. btoa() spread operator in ipns.service.ts

**Location:** `apps/web/src/services/ipns.service.ts:45`
**Added:** 2026-01-21 (Verification Pass)

**Issue:** Uses `btoa(String.fromCharCode(...recordBytes))` which may hit JavaScript's
argument limit for very large arrays. IPNS records are typically small so unlikely
to be an issue in practice.

**Suggested Fix:** Use chunked encoding like `uint8ArrayToBase64()` in metadata.ts.

---

## 11. Incomplete FolderEntry/FileEntry field validation

**Location:** `packages/crypto/src/folder/metadata.ts:49-59`
**Added:** 2026-01-21 (Verification Pass)

**Issue:** The `validateFolderMetadata()` function only validates `type`, `id`, and
`name` fields. Additional fields specific to each type (e.g., `cid`, `fileKeyEncrypted`,
`ipnsName`, `folderKeyEncrypted`) are not validated.

**Impact:** Defense-in-depth only. The metadata is already decrypted with the correct
key (authenticated), so malformed data would cause runtime errors rather than security issues.

**Suggested Fix:**

```typescript
if (entry.type === 'file') {
  if (typeof entry.cid !== 'string' || typeof entry.fileKeyEncrypted !== 'string') {
    throw new CryptoError('Invalid file entry: missing required fields', 'DECRYPTION_FAILED');
  }
}
```

---

## 12. No weak key detection in create-record.ts

**Location:** `packages/crypto/src/ipns/create-record.ts:53`
**Added:** 2026-01-21 (Verification Pass)

**Issue:** While private key size is validated, the key bytes could still be all
zeros or another weak pattern. The `@noble/ed25519` library does not reject weak keys.

**Impact:** A user would need to deliberately provide a weak key, and this is a
single-user system where the key comes from Web3Auth derivation.

**Suggested Fix:**

```typescript
if (ed25519PrivateKey.every((b) => b === 0)) {
  throw new CryptoError('Invalid private key: all zeros', 'INVALID_PRIVATE_KEY_SIZE');
}
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

## 13. Auth Controller Missing Explicit ThrottlerGuard

**Location:** `apps/api/src/auth/auth.controller.ts:42`
**Added:** 2026-02-08 (Phase 9 Desktop Security Review, L-1)

**Issue:** The auth controller does not have `@UseGuards(ThrottlerGuard)`, unlike the IPNS controller. While global ThrottlerModule exists, NestJS requires the guard to be applied per-controller.

**Suggested Fix:** Add `@UseGuards(ThrottlerGuard)` with stricter per-endpoint limits on login (5/min) and refresh (10/min).

---

## 14. IPNS Name in Query Parameter Not URL-Encoded

**Location:** `apps/desktop/src-tauri/src/api/ipns.rs:29`
**Added:** 2026-02-08 (Phase 9 Desktop Security Review, L-2)

**Issue:** `format!("/ipns/resolve?ipnsName={}", ipns_name)` -- no URL encoding. Currently safe (IPNS names are `[a-z0-9]`) but establishes a fragile pattern.

**Suggested Fix:** Use `urlencoding::encode()`.

---

## 15. Debug eprintln! Statements Leak Filenames to stderr

**Location:** `apps/desktop/src-tauri/src/fuse/operations.rs:1638-1641` and others
**Added:** 2026-02-08 (Phase 9 Desktop Security Review, L-3)

**Issue:** Multiple `eprintln!(">>>` statements bypass log-level filtering and leak filenames (sensitive in a privacy-focused app). Already noted in project memory as pre-merge cleanup.

**Suggested Fix:** Remove or replace with `log::debug!()` before merge.

---

## 16. Private Key Logged by Length in auth.ts

**Location:** `apps/desktop/src/auth.ts:167`
**Added:** 2026-02-08 (Phase 9 Desktop Security Review, L-4)

**Issue:** `console.log('Got private key, length:', privateKey.length)` -- logs the length (always 64 hex chars), not the key itself. Not a secret leak, but establishes a risky log-adjacent pattern.

**Suggested Fix:** Remove or reduce to `console.debug`.

---

## 17. Ed25519 Stack Key Copy Not Zeroized

**Location:** `apps/desktop/src-tauri/src/crypto/ed25519.rs:50-56`
**Added:** 2026-02-08 (Phase 9 Desktop Security Review, L-5)

**Issue:** `key_bytes: [u8; 32]` stack copy of Ed25519 private key is not zeroized (the `SigningKey` itself IS auto-zeroized via the `zeroize` feature).

**Suggested Fix:** Call `key_bytes.zeroize()` after creating `SigningKey`.

---

## ~~18. IPNS Sequence Number Fallback to 0 on Resolve Failure~~ — RESOLVED

**Location:** `apps/desktop/src-tauri/src/fuse/operations.rs:1141-1147`
**Added:** 2026-02-08 (Phase 9 Desktop Security Review, L-6)
**Resolved:** 2026-02-10 — Added `PublishCoordinator` with monotonic sequence cache and per-folder publish locks. All 3 publish paths updated.

**Issue:** When IPNS resolve fails, sequence falls back to 0. Publishing with seq=1 when current is seq=100 could cause metadata rollback. Concurrent publishes can also race on the same sequence number.

**Impact:** Silent data loss (overwrites), metadata rollback to stale state.

**Suggested Fix:** Cache last-known sequence number locally and never go below it; return error if unable to resolve current sequence.

---

## 19. Sync Daemon Error Messages Exposed Raw in Tray Status

**Location:** `apps/desktop/src-tauri/src/sync/mod.rs:158-161`
**Added:** 2026-02-08 (Phase 9 Desktop Security Review, L-7)

**Issue:** Raw error strings (potentially containing API URLs, CIDs, internal info) passed to tray status display.

**Suggested Fix:** Map to user-friendly messages; log full errors internally.

---

_Generated from security:review command - Phase 5, Phase 9_
