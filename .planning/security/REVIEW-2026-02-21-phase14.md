# Security Review Report

**Date:** 2026-02-21
**Scope:** Phase 14 - User-to-User Sharing (all 66 files, 6 subphases)
**Reviewer:** Claude (security:review command)
**Branch:** `feat/phase-14-user-to-user-sharing`

## Executive Summary

Phase 14 implements user-to-user sharing with a sound fundamental architecture: ECIES key re-wrapping is performed entirely client-side, the server stores only ciphertexts, and plaintext keys are zeroed after use in most code paths. However, the review identified **one critical functional gap** (file keys not re-wrapped during folder sharing), **three high-severity issues** (missing input validation, user ID exposure, unique constraint conflict with soft-delete), and several medium/low items.

**Risk Level:** HIGH (due to the file key gap and missing DTO validation)

## Files Reviewed

| File                                                   | Crypto Operations                           | Risk Level |
| ------------------------------------------------------ | ------------------------------------------- | ---------- |
| `packages/crypto/src/ecies/rewrap.ts`                  | ECIES unwrap + wrap, plaintext zeroing      | LOW        |
| `packages/crypto/src/ecies/encrypt.ts`                 | ECIES wrap (curve point validation)         | LOW        |
| `packages/crypto/src/ecies/decrypt.ts`                 | ECIES unwrap (GCM auth)                     | LOW        |
| `apps/api/src/shares/shares.service.ts`                | None (stores ciphertexts only)              | MEDIUM     |
| `apps/api/src/shares/shares.controller.ts`             | None (JWT auth, authorization)              | MEDIUM     |
| `apps/api/src/shares/dto/create-share.dto.ts`          | Input validation for crypto payloads        | HIGH       |
| `apps/api/src/shares/dto/share-key.dto.ts`             | Input validation for crypto payloads        | HIGH       |
| `apps/api/src/shares/dto/update-encrypted-key.dto.ts`  | Input validation for crypto payloads        | HIGH       |
| `apps/api/src/shares/entities/share.entity.ts`         | Stores ECIES ciphertext (bytea)             | LOW        |
| `apps/api/src/shares/entities/share-key.entity.ts`     | Stores ECIES ciphertext (bytea)             | LOW        |
| `apps/web/src/services/share.service.ts`               | ECIES wrap, key zeroing, lazy rotation      | MEDIUM     |
| `apps/web/src/hooks/useSharedNavigation.ts`            | ECIES unwrap, folder key management         | MEDIUM     |
| `apps/web/src/components/file-browser/ShareDialog.tsx` | ECIES unwrap/wrap, recursive key collection | HIGH       |
| `apps/web/src/hooks/useFolder.ts`                      | Post-upload re-wrap, key zeroing            | LOW        |
| `apps/web/src/services/folder.service.ts`              | Lazy rotation orchestration                 | MEDIUM     |
| `apps/web/src/stores/share.store.ts`                   | State management (no crypto)                | LOW        |
| `apps/web/src/routes/SettingsPage.tsx`                 | Public key display/copy                     | LOW        |

## Findings

### Critical Issues

_None found in the cryptographic implementation itself._

### High Priority

#### H1. File Keys Not Re-Wrapped During Folder Sharing

- **Severity:** HIGH
- **Location:** `apps/web/src/components/file-browser/ShareDialog.tsx:78-96` (`collectChildKeys`)
- **Description:** When sharing a folder, `collectChildKeys` recursively re-wraps subfolder keys but **skips file keys entirely**. The code has extensive comments about needing to re-wrap file keys but ends with `void fp;` and moves on. The recipient gets subfolder keys via `share_keys` but no file keys.
- **Impact:** Recipients can navigate shared folders and see file listings, but **cannot download any files** that existed at the time the share was created. Only files uploaded _after_ sharing (via the post-upload re-wrap hook in `useFolder.ts`) are downloadable. The fallback in `useSharedNavigation.ts:412-424` tries `fileMeta.fileKeyEncrypted`, which is wrapped for the **owner's** public key, so `unwrapKey` with the recipient's private key will fail.
- **Recommendation:** In `collectChildKeys`, for each `child.type === 'file'`, resolve the file metadata via its `fileMetaIpnsName`, extract `fileKeyEncrypted`, unwrap it with the owner's private key, re-wrap with the recipient's public key, and add to `childKeys` as `keyType: 'file'`. Example:

  ```typescript
  if (child.type === 'file') {
    const fp = child as FilePointer;
    const { metadata: fileMeta } = await resolveFileMetadata(fp.fileMetaIpnsName, currentFolderKey);
    const reWrappedFileKey = await reWrapEncryptedKey(
      fileMeta.fileKeyEncrypted,
      ownerPrivateKey,
      recipientPubKeyBytes
    );
    childKeys.push({
      keyType: 'file',
      itemId: fp.id,
      encryptedKey: reWrappedFileKey,
    });
    wrapped++;
    onProgress(wrapped);
  }
  ```

  Also update `countFolderChildren` to count all children (not just folders) for accurate progress.

#### H2. Missing Input Validation on Hex-Encoded Fields in DTOs

- **Severity:** HIGH
- **Location:** `apps/api/src/shares/dto/create-share.dto.ts`, `share-key.dto.ts`, `update-encrypted-key.dto.ts`
- **Description:** All `encryptedKey` fields use only `@IsString()` with no format validation. The `recipientPublicKey` field likewise has no format constraints. This allows:
  - Non-hex strings to be stored (corrupting data)
  - Extremely large strings (DoS via storage)
  - SQL-injection-like payloads in string fields (mitigated by TypeORM parameterization but defense-in-depth)
- **Impact:** Malicious client could store arbitrary data in the `encrypted_key` bytea column (via `Buffer.from(nonHex, 'hex')` which returns an empty buffer for invalid hex), or cause storage bloat.
- **Recommendation:** Add validation decorators:

  ```typescript
  // For encryptedKey fields:
  @Matches(/^[0-9a-fA-F]+$/)
  @MinLength(2)    // At minimum a single byte
  @MaxLength(1024) // ECIES ciphertext for 32-byte key is ~113 bytes = 226 hex chars
  encryptedKey!: string;

  // For recipientPublicKey:
  @Matches(/^(0x)?04[0-9a-fA-F]{128}$/)
  recipientPublicKey!: string;

  // For itemId:
  @IsUUID()
  itemId!: string;

  // For ipnsName:
  @Matches(/^k51[a-z0-9]+$/)
  ipnsName!: string;

  // For itemName:
  @MaxLength(255)
  itemName!: string;
  ```

#### H3. User ID Exposure via Lookup Endpoint

- **Severity:** HIGH
- **Location:** `apps/api/src/shares/shares.controller.ts:144-152`, `shares.service.ts:222-234`
- **Description:** `GET /shares/lookup?publicKey=X` returns `{ userId: <UUID>, publicKey: <key> }`. Any authenticated user can learn the internal UUID of any other user by querying their public key. Combined with other endpoints, this could enable targeted attacks.
- **Impact:** Internal user UUIDs should not be exposed. The share creation flow only needs to know the user _exists_ (the server resolves the recipient internally by public key).
- **Recommendation:** Change the response to `{ exists: true }` or remove the `userId` from the response. The server-side `createShare` already looks up the recipient by `recipientPublicKey`, so the client doesn't need the userId.

#### H4. Unique Constraint Conflicts with Soft-Delete Revocation

- **Severity:** HIGH
- **Location:** `apps/api/src/shares/entities/share.entity.ts:17`
- **Description:** `@Unique(['sharerId', 'recipientId', 'ipnsName'])` prevents duplicate records. After revocation (`revokedAt` is set), the record still exists until lazy rotation hard-deletes it. During this window, the sharer **cannot re-share** the same item with the same recipient (or a different item at the same IPNS name) because the unique constraint blocks insertion.
- **Impact:** After revoking a share, the sharer must modify the folder (triggering rotation + hard-delete) before they can re-share with the same recipient. This creates confusing UX and could be perceived as a bug.
- **Recommendation:** Either:
  - (a) Create a partial unique index that only applies to non-revoked records: remove the `@Unique` decorator and add a migration with `CREATE UNIQUE INDEX shares_active_unique ON shares(sharer_id, recipient_id, ipns_name) WHERE revoked_at IS NULL;`
  - (b) Change `createShare` to delete-then-recreate if a revoked record exists for the same triple
  - Option (a) is cleaner and handles all edge cases.

### Medium Priority

#### M1. Plaintext `itemName` Stored on Server

- **Severity:** MEDIUM
- **Location:** `apps/api/src/shares/entities/share.entity.ts:49`
- **Description:** The `itemName` field is stored unencrypted. File/folder names can reveal sensitive information (e.g., "2026-tax-returns", "medical-records"). The server, which is designed to be zero-knowledge about content, can see what items are being shared.
- **Impact:** Metadata leakage. The server operator can see file/folder names of shared items.
- **Recommendation:** For v1, document this as a known privacy trade-off. For future work, encrypt `itemName` with the recipient's public key (the recipient's client would decrypt it for display). This requires more complex key management but aligns with the zero-knowledge design.

#### M2. `reWrapForRecipients` Does Not Zero Plaintext Keys

- **Severity:** MEDIUM
- **Location:** `apps/web/src/services/share.service.ts:281-332`
- **Description:** `reWrapForRecipients` receives `params.newItems[*].plaintextKey` (raw Uint8Array key material) and wraps it for each recipient, but never zeros the plaintext after all wrapping is complete. While the callers in `useFolder.ts` handle zeroing for file upload cases (via `finally` blocks), this defense-in-depth gap means:
  - If a new caller is added that forgets to zero, keys leak
  - The function signature accepts plaintext keys without documenting the zeroing contract
- **Impact:** Plaintext keys remain in memory longer than necessary.
- **Recommendation:** Document the zeroing contract in the function's JSDoc. Consider adding a `finally` block that zeros `params.newItems[*].plaintextKey`, but be careful: for the subfolder creation case, the key is also stored in the folder store and should NOT be zeroed. A better approach is to accept wrapped keys and let the function unwrap internally (like the `reWrapKey` primitive does).

#### M3. Folder Key Not Zeroed on Navigation Away

- **Severity:** MEDIUM
- **Location:** `apps/web/src/hooks/useSharedNavigation.ts:306-314` (`navigateToRoot`)
- **Description:** When navigating away from a shared folder, `navigateToRoot` sets `folderKey` to `null` via React state, but the `Uint8Array` is not zeroed first. The decrypted folder key remains in JavaScript heap memory until garbage collected.
- **Impact:** Decrypted key material lingers in memory. In a browser context, this is hard to exploit directly, but violates the principle of minimizing key exposure time.
- **Recommendation:** Zero the key before clearing state:

  ```typescript
  const navigateToRoot = useCallback(() => {
    if (folderKey) folderKey.fill(0);
    // Also zero nav stack keys
    for (const entry of navStackRef.current) {
      entry.folderKey.fill(0);
    }
    setCurrentView('list');
    // ...
  }, [folderKey]);
  ```

#### M4. Share Keys Cache Never Invalidated

- **Severity:** MEDIUM
- **Location:** `apps/web/src/hooks/useSharedNavigation.ts:99-103`
- **Description:** The `shareKeysCache` ref holds re-wrapped keys per shareId but is never invalidated. If the sharer adds new files (via post-upload `addShareKeys`), the recipient won't see the new keys until remounting the component.
- **Impact:** Files uploaded after the initial navigation into a shared folder won't be downloadable until the user navigates away and back.
- **Recommendation:** Add a TTL (e.g., 60s) to the cache, or invalidate on `navigateToShare` re-entry.

#### M5. Silent Failure in Re-Wrapping for Recipients

- **Severity:** MEDIUM
- **Location:** `apps/web/src/services/share.service.ts:325-330`
- **Description:** If `wrapKey` or `addShareKeys` fails for one recipient, the error is logged as a warning and processing continues. The share exists but the recipient has no keys for the newly added items.
- **Impact:** Inconsistent state: recipient sees the shared folder but can't access specific files/subfolders. No user-visible indication that re-wrapping failed.
- **Recommendation:** At minimum, surface a non-blocking notification to the sharer. Consider a background retry queue for failed re-wrapping operations.

### Low Priority / Recommendations

#### L1. `lookupUser` Enables Public Key Enumeration

- **Severity:** LOW
- **Location:** `apps/api/src/shares/shares.controller.ts:131-152`
- **Description:** The 200/404 distinction confirms whether a public key belongs to a registered user. Combined with the throttler guard, an attacker can enumerate users at the rate limit.
- **Impact:** Information disclosure about registered user set.
- **Recommendation:** Consider always returning 200 with `{ exists: boolean }` (already somewhat mitigated by requiring authentication).

#### L2. `executeLazyRotation` Doesn't Zero `newFolderKey`

- **Severity:** LOW
- **Location:** `apps/web/src/services/share.service.ts:422, 466`
- **Description:** The generated 32-byte key is returned to the caller but never zeroed inside `executeLazyRotation`. The caller (`checkAndRotateIfNeeded`) stores it in the folder store but also doesn't zero the intermediate variable.
- **Impact:** Minor memory hygiene issue. The key is actively used (stored in store), so zeroing the local variable alone wouldn't help much.
- **Recommendation:** Accept as technical debt for now; the key is actively in use.

#### L3. `Buffer.from(hex, 'hex')` Silently Truncates Invalid Hex

- **Severity:** LOW
- **Location:** `apps/api/src/shares/shares.service.ts:65, 79, 166, 288`
- **Description:** Node.js `Buffer.from(str, 'hex')` silently ignores non-hex characters and truncates at the first invalid char. If DTO validation doesn't ensure valid hex (see H2), corrupted data could be stored.
- **Impact:** Data integrity issue (would cause decryption failures on the client).
- **Recommendation:** Addressed by fixing H2 (adding `@Matches` hex validation to DTOs).

#### L4. No Pagination on Share Listing Endpoints

- **Severity:** LOW
- **Location:** `apps/api/src/shares/shares.controller.ts:73-101, 103-129`
- **Description:** `getReceivedShares` and `getSentShares` return all shares without pagination. A user with many shares could see slow responses and high memory usage.
- **Impact:** Performance issue at scale; minor DoS vector.
- **Recommendation:** Add pagination parameters (`limit`, `offset`) for future scalability.

---

## Detailed Analysis

### `packages/crypto/src/ecies/rewrap.ts`

**What it does:** Unwraps a key with the owner's private key, re-wraps it with the recipient's public key, zeroes the plaintext.

**Crypto operations:**

- `unwrapKey` (ECIES decrypt via eciesjs)
- `wrapKey` (ECIES encrypt via eciesjs)
- `plainKey.fill(0)` (memory zeroing)

**Issues found:** None. This is well-implemented.

**Positive observations:**

- Plaintext key zeroed in both success and error paths
- Generic error message prevents information leakage
- Proper `try/catch` with `finally`-like cleanup pattern
- Delegates to validated `wrapKey`/`unwrapKey` primitives

### `packages/crypto/src/ecies/encrypt.ts` / `decrypt.ts`

**What it does:** ECIES key wrapping using eciesjs library.

**Positive observations:**

- Public key size validation (65 bytes uncompressed)
- Prefix validation (0x04)
- Curve point validation via `ProjectivePoint.fromHex`
- Private key size validation (32 bytes)
- Minimum ciphertext size check
- Generic error messages prevent oracle attacks
- Uses AES-GCM internally (via eciesjs) for authenticated encryption

### `apps/web/src/components/file-browser/ShareDialog.tsx`

**What it does:** UI for creating shares, with recursive key collection for folder sharing.

**Crypto operations:**

- `unwrapKey` (to get subfolder keys from owner-encrypted form)
- `wrapKey` (to re-wrap for recipient)
- Recursive `collectChildKeys` for depth-first folder traversal
- `reWrapEncryptedKey` helper (unwrap + wrap + zero)

**Issues found:**

1. **H1 - File keys skipped in `collectChildKeys`** (see above)
2. The `reWrapEncryptedKey` helper correctly zeros the plaintext key at line 159 -- good.
3. `itemFolderKey` is zeroed at line 339 after use -- good.
4. `folderKeyBytes` in recursive `collectChildKeys` is zeroed at line 126 -- good.

**Positive observations:**

- Client-side validation prevents self-sharing (line 270)
- Public key format validation before any crypto operations
- Inline revoke with two-step confirmation prevents accidental revocation
- Root folder sharing blocked

### `apps/api/src/shares/shares.service.ts`

**What it does:** Server-side share lifecycle management. Never touches plaintext keys.

**Issues found:**

1. **H4 - Unique constraint conflict** (see above)
2. The `addShareKeys` method uses sequential queries for upsert (line 156-177). Under concurrent requests, this could lead to duplicate key entries or race conditions. Should use database-level upsert (`ON CONFLICT DO UPDATE`).

**Positive observations:**

- Proper authorization checks on every method (sharerId/recipientId matching)
- Self-share prevention
- Duplicate active share prevention
- CASCADE delete for ShareKey cleanup
- Server never processes or inspects key material

### `apps/web/src/services/share.service.ts`

**What it does:** Client-side share service with re-wrapping, lazy rotation, and cache management.

**Crypto operations:**

- `wrapKey` in `reWrapForRecipients` (line 315)
- `wrapKey` in `executeLazyRotation` (line 444)
- `generateRandomBytes(32)` for new folder key generation (line 422)

**Issues found:**

1. **M2 - Plaintext keys not zeroed** (see above)
2. **M5 - Silent failure in re-wrapping** (see above)
3. `executeLazyRotation` line 464 clears the sent shares cache by setting to `[]` -- this also resets `lastFetchedAt` via `setSentShares`, which is correct for invalidation.

**Positive observations:**

- Correct use of `useShareStore.getState()` to avoid stale Zustand closures
- 30-second cache TTL for sent shares reduces unnecessary API calls
- `hexToBytes` correctly handles `0x` prefix stripping (line 303-305)

### `apps/web/src/hooks/useSharedNavigation.ts`

**What it does:** Navigation hook for browsing received shared content.

**Crypto operations:**

- `unwrapKey` to decrypt share record's `encryptedKey` (line 177)
- `unwrapKey` to decrypt subfolder keys from `share_keys` (line 238)
- `decryptFolderMetadata` with unwrapped key (line 193, 261)
- `decryptFileMetadata` with folder key (line 342, 392)

**Issues found:**

1. **M3 - Folder key not zeroed on navigation away** (see above)
2. **M4 - Share keys cache never invalidated** (see above)
3. **Fallback download path will always fail** (line 412-424) - `fileMeta.fileKeyEncrypted` is wrapped for the owner, not the recipient. This path should be removed or documented as dead code once H1 is fixed.

**Positive observations:**

- Proper use of `useRef` for navigation stack (avoids stale closures)
- Cleanup function in `useEffect` prevents state updates after unmount
- Error handling on all async paths

### `apps/web/src/services/folder.service.ts` (`checkAndRotateIfNeeded`)

**What it does:** Lazy key rotation before folder modifications.

**Crypto operations:**

- Delegates to `executeLazyRotation` (generates new key, re-wraps)
- `fetchAndDecryptMetadata` (decrypt with old key)
- `updateFolderMetadata` (re-encrypt with new key)

**Issues found:**

1. **L2 - `newFolderKey` not zeroed** (see above)
2. The function doesn't update the parent folder's `folderKeyEncrypted` for the rotated child (documented in comments at line 958-962). If the calling code doesn't handle this, the parent folder will reference the old key.

**Positive observations:**

- Dynamic import to avoid circular dependency
- Graceful fallback if vault keypair is unavailable

---

## Compliance Checklist

Based on project security rules:

- [x] No privateKey in localStorage/sessionStorage
- [x] No sensitive keys logged (only truncated public keys in warnings)
- [x] No unencrypted keys sent to server (all keys ECIES-wrapped before API calls)
- [x] ECIES used for key wrapping (via eciesjs library)
- [x] AES-256-GCM used for content encryption (via eciesjs internally for key wrapping; existing folder/file encryption unchanged)
- [x] Server has zero knowledge of plaintext keys (stores only ECIES ciphertexts and encrypted metadata)
- [x] IPNS keys not exposed in sharing flow (recipient gets decryption keys only, never IPNS signing keys)
- [x] Plaintext keys zeroed after use in most code paths (see M2, M3 for gaps)

---

## Test Cases

### `packages/crypto/src/ecies/rewrap.ts`

#### Existing Tests (4 vectors - adequate)

- Round-trip: wrap -> re-wrap -> unwrap yields same key ✓
- Multi-recipient: re-wrap for multiple recipients ✓
- Wrong owner key: fails with CryptoError ✓
- Invalid recipient key: fails with CryptoError ✓

#### Additional Tests Needed

```typescript
describe('reWrapKey edge cases', () => {
  it('should zero plaintext even on wrapKey failure', async () => {
    // Use valid owner key but a public key that passes format validation
    // but fails at the eciesjs level
    const alice = generateTestKeypair();
    const originalKey = generateRandomBytes(32);
    const wrapped = await wrapKey(originalKey, alice.publicKey);

    // Spy on wrapKey to make it throw after unwrap succeeds
    // Verify plainKey.fill(0) was called
  });

  it('should handle empty key (0 bytes) re-wrapping', async () => {
    const alice = generateTestKeypair();
    const bob = generateTestKeypair();
    const emptyKey = new Uint8Array(0);
    const wrapped = await wrapKey(emptyKey, alice.publicKey);
    const reWrapped = await reWrapKey(wrapped, alice.privateKey, bob.publicKey);
    const result = await unwrapKey(reWrapped, bob.privateKey);
    expect(result.length).toBe(0);
  });

  it('should handle large key (64 bytes) re-wrapping', async () => {
    const alice = generateTestKeypair();
    const bob = generateTestKeypair();
    const largeKey = generateRandomBytes(64);
    const wrapped = await wrapKey(largeKey, alice.publicKey);
    const reWrapped = await reWrapKey(wrapped, alice.privateKey, bob.publicKey);
    const result = await unwrapKey(reWrapped, bob.privateKey);
    expect(result).toEqual(largeKey);
  });
});
```

### API Authorization Tests

```typescript
describe('SharesController authorization', () => {
  it('should reject getShareKeys when user is neither sharer nor recipient', async () => {
    // Create share between Alice and Bob
    // Try to access keys as Charlie
    // Expect 403
  });

  it('should reject addShareKeys when user is not the sharer', async () => {
    // Create share from Alice to Bob
    // Bob tries to addShareKeys
    // Expect 403
  });

  it('should reject revokeShare when user is not the sharer', async () => {
    // Create share from Alice to Bob
    // Bob tries to revoke
    // Expect 403
  });

  it('should reject hideShare when user is not the recipient', async () => {
    // Create share from Alice to Bob
    // Alice tries to hide
    // Expect 403
  });

  it('should reject createShare with non-registered publicKey', async () => {
    // Generate random valid secp256k1 pubkey
    // Try to create share
    // Expect 404
  });

  it('should reject createShare with own publicKey', async () => {
    // Expect 409
  });

  it('should reject duplicate active share', async () => {
    // Create share Alice -> Bob for folder X
    // Try to create again
    // Expect 409
  });
});
```

### Lazy Rotation Integration Tests

```typescript
describe('Lazy key rotation', () => {
  it('should generate new folderKey and re-wrap for remaining recipients', async () => {
    // Share folder with Bob and Charlie
    // Revoke Bob's share
    // Trigger folder modification (should trigger lazy rotation)
    // Verify: new key generated, Charlie gets re-wrapped key, Bob's share deleted
  });

  it('should handle rotation when all shares are revoked', async () => {
    // Share folder with Bob
    // Revoke Bob's share
    // Trigger rotation
    // Verify: new key generated, Bob's share deleted, no re-wrapping needed
  });

  it('should handle concurrent rotation attempts', async () => {
    // Two folder modifications happen near-simultaneously
    // Verify no double-rotation or key inconsistency
  });
});
```

### Attack Scenarios to Test

- [ ] **Key confusion attack** -- Create share with `encryptedKey` that's actually a valid ECIES ciphertext for a _different_ key. Verify recipient gets garbled data (fails safely), not some other user's key.
- [ ] **Replay attack** -- Replay a `createShare` request with the same body. Verify 409 (duplicate share prevention).
- [ ] **Privilege escalation** -- Recipient tries to modify shared content (no write access by design). Verify all modification endpoints check ownership.
- [ ] **Enumeration** -- Brute-force `GET /shares/lookup?publicKey=...` to map registered public keys. Verify throttler rate limits are effective.
- [ ] **IDOR** -- Access another user's share keys via `GET /shares/:shareId/keys` with a guessed UUID. Verify 403 (authorization check on line 130 of shares.service.ts).

---

## Recommendations Summary

| Priority | Finding                                              | Recommendation                                                   | Effort |
| -------- | ---------------------------------------------------- | ---------------------------------------------------------------- | ------ |
| P0       | H1: File keys not re-wrapped in folder sharing       | Add file key re-wrapping to `collectChildKeys`                   | MEDIUM |
| P0       | H2: Missing DTO input validation                     | Add `@Matches`, `@MinLength`, `@MaxLength`, `@IsUUID` decorators | LOW    |
| P1       | H3: User ID exposed in lookup                        | Return `{ exists: true }` instead of `{ userId, publicKey }`     | LOW    |
| P1       | H4: Unique constraint vs soft-delete                 | Use partial unique index with `WHERE revoked_at IS NULL`         | LOW    |
| P2       | M1: Plaintext itemName on server                     | Document as known trade-off; encrypt in future                   | LOW    |
| P2       | M2: Plaintext keys not zeroed in reWrapForRecipients | Document zeroing contract; consider accepting wrapped keys       | LOW    |
| P2       | M3: Folder key not zeroed on navigation away         | Add `folderKey.fill(0)` before clearing state                    | LOW    |
| P2       | M4: Share keys cache never invalidated               | Add TTL or invalidation on re-entry                              | LOW    |
| P2       | M5: Silent re-wrapping failures                      | Surface non-blocking notification to sharer                      | MEDIUM |
| P3       | L1-L4: Various low-priority items                    | See individual recommendations                                   | LOW    |

## Next Steps

1. **Immediate (P0):** Fix H1 (file key re-wrapping) and H2 (DTO validation) before merging PR
2. **Before merge (P1):** Fix H3 (user ID exposure) and H4 (unique constraint)
3. **Post-merge (P2-P3):** Address medium/low items as tech debt in future phases

---

_Generated by security:review command_
_This review is automated guidance, not a substitute for professional security audit_
