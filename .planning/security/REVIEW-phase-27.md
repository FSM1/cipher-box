# Security Review: Phase 27 - Writable Shares PoC

**Reviewer:** Claude Opus 4.6 (Security Agent)
**Date:** 2026-03-26
**Scope:** All code changes in Phase 27 (writable shares), spanning API backend and web frontend
**Branch:** `feat/phase-27-writable-shares-poc`

---

## SECURITY REVIEW COMPLETE

**Files analyzed:** 16
**Crypto operations found:** 18
**Issues found:** 2 Critical, 3 High, 4 Medium, 3 Low

---

## Critical Issues

### [CRITICAL] C-01: Stale Sequence Number in Conflict Retry Causes Data Loss

**Location:** `apps/web/src/hooks/useSharedNavigation.ts:909-925` (uploadFile), also lines 1050-1066 (createFolder), 1113-1132 (rename), 1296-1313 (delete)

**Code:**

```typescript
await withConflictRetry(
  async () => {
    const freshChildren = [...folderChildren, filePointer];
    const newSeq = await publishSharedFolderMetadata(
      freshChildren,
      currentFolderKey,
      currentIpnsName,
      currentIpnsKey,
      currentSequenceNumber ?? 0n // <-- captures stale closure value
    );
    setCurrentSequenceNumber(newSeq);
    setFolderChildren(freshChildren);
  },
  async () => {
    await resyncSharedFolder();
  }
);
```

**Issue:**
The `withConflictRetry` pattern works as follows: on 409, it calls the `syncFn` (resyncSharedFolder), then retries the operation. However, `resyncSharedFolder` updates React state (`setCurrentSequenceNumber`, `setFolderChildren`), but the retry closure still captures the **stale** `currentSequenceNumber` and `folderChildren` from the initial render. The resync updates state, but because React batches state updates, the retry runs with the old values. This means:

1. First attempt fails with 409 (sequence mismatch)
2. `resyncSharedFolder()` runs, calling `refreshFolderContents()` which calls `setCurrentSequenceNumber(resolved.sequenceNumber)` and `setFolderChildren(metadata.children)`
3. Retry fires immediately -- but the closure still has the OLD `currentSequenceNumber` and OLD `folderChildren`
4. The retry will fail again with 409, or worse, overwrite concurrent changes with stale data

This is the **exact** "Zustand stale closures in async callbacks" pattern documented in the project memory. The owner's `useFolderMutations` avoids this by using `useFolderStore.getState()` for fresh reads. Here, there is no store backing the shared folder state -- it is all React `useState`.

**Impact:**
Multi-writer conflicts (the primary use case for writable shares) will reliably lose data. When two writers modify the same folder within 30 seconds of each other, the retry will fail or produce corrupted metadata.

**Recommendation:**
Use refs alongside state for values that must be fresh in retry closures:

```typescript
const sequenceNumberRef = useRef<bigint | null>(null);
const folderChildrenRef = useRef<FolderChild[]>([]);

// In refreshFolderContents, update both state and ref:
const refreshFolderContents = useCallback(async (...) => {
  // ...
  setFolderChildren(metadata.children ?? []);
  folderChildrenRef.current = metadata.children ?? [];
  setCurrentSequenceNumber(resolved.sequenceNumber);
  sequenceNumberRef.current = resolved.sequenceNumber;
  // ...
});

// In retry closures, read from refs:
await withConflictRetry(
  async () => {
    const freshChildren = [...folderChildrenRef.current, filePointer];
    const seqNum = sequenceNumberRef.current ?? 0n;
    const newSeq = await publishSharedFolderMetadata(
      freshChildren, currentFolderKey, currentIpnsName, currentIpnsKey, seqNum
    );
    sequenceNumberRef.current = newSeq;
    folderChildrenRef.current = freshChildren;
    setCurrentSequenceNumber(newSeq);
    setFolderChildren(freshChildren);
  },
  async () => { await resyncSharedFolder(); }
);
```

---

### [CRITICAL] C-02: Subfolder Keys Wrapped with Recipient's Own Key -- Owner Cannot Access

**Location:** `apps/web/src/hooks/useSharedNavigation.ts:1009-1018` (createFolderHandler)

**Code:**

```typescript
const wrappedFolderKey = await wrapSubfolderKey(
  subfolderKey,
  auth.vaultKeypair.publicKey // <-- recipient's key
);
const wrappedIpnsKey = await wrapSubfolderKey(
  keypair.privateKey,
  auth.vaultKeypair.publicKey // <-- recipient's key
);
```

**Issue:**
When a write-share recipient creates a subfolder, the `folderKeyEncrypted` and `ipnsPrivateKeyEncrypted` fields in the `FolderEntry` are wrapped with the **recipient's** public key, not the **owner's** public key. This means:

1. The **owner** cannot unwrap the subfolder's key or IPNS key from the FolderEntry -- they would need the recipient's private key
2. The **owner** cannot navigate into subfolders created by recipients
3. The **owner** cannot modify or delete these subfolders
4. If the share is revoked, the owner permanently loses access to those subfolders and all content within them
5. Other write-share recipients also cannot access these subfolders (they don't have the first recipient's private key)

The owner path (`useFolderMutations`) wraps these keys with the owner's public key, which is correct because the FolderEntry's key fields are the canonical owner-decryptable copies.

**Impact:**
Data loss. Subfolders created by write-share recipients become inaccessible to the owner and all other recipients. This fundamentally breaks the sharing model and violates the key hierarchy.

**Recommendation:**
Wrap with the **owner's** public key (from the share record) for the FolderEntry fields. Additionally, add a `share_keys` entry with the recipient's copy:

```typescript
// Get owner's public key from the share
const shareItem = sharedItems.find((s) => s.share.shareId === currentShareId);
const ownerPubKeyHex = shareItem.share.sharerPublicKey.startsWith('0x')
  ? shareItem.share.sharerPublicKey.slice(2)
  : shareItem.share.sharerPublicKey;
const ownerPublicKey = hexToBytes(ownerPubKeyHex);

// Wrap for OWNER (goes into FolderEntry -- canonical copy)
const wrappedFolderKeyForOwner = await wrapSubfolderKey(subfolderKey, ownerPublicKey);
const wrappedIpnsKeyForOwner = await wrapSubfolderKey(keypair.privateKey, ownerPublicKey);

// Build FolderEntry with owner-wrapped keys
const folderEntry: FolderEntry = {
  // ...
  ipnsPrivateKeyEncrypted: bytesToHex(wrappedIpnsKeyForOwner),
  folderKeyEncrypted: bytesToHex(wrappedFolderKeyForOwner),
};

// Also add share_keys for the recipient (so THEY can access)
const recipientWrappedFolderKey = await wrapSubfolderKey(
  subfolderKey,
  auth.vaultKeypair!.publicKey
);
await addShareKeys(currentShareId!, [
  { keyType: 'folder', itemId: folderId, encryptedKey: bytesToHex(recipientWrappedFolderKey) },
]).catch((err) => console.warn('[share] Failed to add subfolder share_key:', err));
```

---

## High Priority Issues

### [HIGH] H-01: Write-Share Recipient Can Inject Arbitrary encryptedIpnsPrivateKey via IPNS Publish

**Location:** `apps/api/src/ipns/ipns.service.ts:220-246`

**Code:**

```typescript
// Only update encrypted key if provided (e.g., on key rotation)
if (encryptedIpnsPrivateKey && keyEpoch !== undefined) {
  existing.encryptedIpnsPrivateKey = Buffer.from(encryptedIpnsPrivateKey, 'hex');
  existing.keyEpoch = keyEpoch;
}
// ...
if (encryptedIpnsPrivateKey && keyEpoch !== undefined) {
  this.republishService
    .enrollFolder(
      existing.userId,  // Uses FolderIpns owner
      ipnsName,
      Buffer.from(encryptedIpnsPrivateKey, 'hex'),
      keyEpoch,
      metadataCid,
      saved.sequenceNumber
    )
```

**Issue:**
When a write-share recipient publishes to a shared IPNS name, the `publishRecord` method accepts `encryptedIpnsPrivateKey` and `keyEpoch` parameters from the client. If the recipient sends these fields, the server will:

1. **Overwrite** the owner's `encryptedIpnsPrivateKey` on the `FolderIpns` row
2. **Re-enroll** the folder with TEE using the recipient-supplied key

This allows a malicious write-share recipient to:

- Replace the TEE-encrypted IPNS private key with garbage, breaking TEE republishing for the owner
- Supply a key encrypted for a different TEE public key, potentially causing republishing failures
- If the recipient knows the TEE public key, they could wrap a different IPNS key, causing the TEE to republish incorrect records

The write-share recipient should only be able to update `latestCid` and `sequenceNumber`, never the IPNS key enrollment data.

**Impact:**
A malicious write-share recipient can sabotage TEE republishing for the shared folder, causing IPNS records to go stale (IPNS records expire after ~48 hours without republishing).

**Recommendation:**
Block `encryptedIpnsPrivateKey` and `keyEpoch` updates from write-share recipients:

```typescript
// In upsertFolderIpns, after the write-share authorization path:
const isWriteSharePublish = existing && existing.userId !== userId;

// Only update encrypted key if provided AND the caller is the owner (not write-share)
if (encryptedIpnsPrivateKey && keyEpoch !== undefined && !isWriteSharePublish) {
  existing.encryptedIpnsPrivateKey = Buffer.from(encryptedIpnsPrivateKey, 'hex');
  existing.keyEpoch = keyEpoch;
}
```

---

### [HIGH] H-02: Fallback to `fileKeyEncrypted` in Shared Download Creates Key Confusion

**Location:** `apps/web/src/hooks/useSharedNavigation.ts:663`

**Code:**

```typescript
const wrappedKey = fileKeyRecord?.encryptedKey ?? fileMeta.fileKeyEncrypted;
```

Also at `apps/web/src/components/file-browser/TextEditorDialog.tsx:103`:

```typescript
const wrappedKey = fileKeyRecord?.encryptedKey ?? fileMeta.fileKeyEncrypted;
```

**Issue:**
This fallback is documented as "for files uploaded by current user" but creates a subtle security inconsistency:

1. `fileKeyRecord.encryptedKey` is the file key wrapped with the **recipient's** public key (from `share_keys` table)
2. `fileMeta.fileKeyEncrypted` is the file key wrapped with the **owner's** public key (stored in file IPNS metadata)

When a recipient uploads a file to a write-shared folder (using the upload handler at line 834), the `fileKeyEncrypted` in file metadata is wrapped with the **owner's** public key:

```typescript
const ownerWrappedKey = await wrapKey(fileKey, ownerPublicKey);
const fileKeyEncrypted = bytesToHex(ownerWrappedKey);
```

So `fileMeta.fileKeyEncrypted` is ONLY unwrappable by the **owner**. If the `share_keys` entry is missing for a recipient (race condition, network failure in the fire-and-forget `addShareKeys` call at line 931-944), the fallback to `fileMeta.fileKeyEncrypted` will cause an ECIES unwrap failure for the recipient. This is a silent crypto failure -- the error message will be a generic "decryption failed" rather than an informative "share key not found."

For files uploaded by the **owner** that predate the share: if the owner has not re-wrapped the key via `reWrapForRecipients`, `fileMeta.fileKeyEncrypted` is wrapped with the owner's key and the recipient cannot decrypt either way. The fallback provides no value and masks the real problem.

**Impact:**

- Silent decryption failures with confusing error messages
- For owner-uploaded files pre-share: fallback always fails (wrapped with owner's key)
- For recipient-uploaded files when share_key is missing: fallback always fails (wrapped with owner's key)
- The only case where the fallback works: recipient uploaded the file AND the `share_keys` write succeeded. In this case `fileKeyRecord` exists and the fallback is not reached anyway.

**Recommendation:**
Replace the silent fallback with an explicit error:

```typescript
const fileKeyRecord = keys.find((k) => k.keyType === 'file' && k.itemId === item.id);
if (!fileKeyRecord) {
  throw new Error('File key not available -- the file owner may need to re-share this folder');
}
const wrappedKey = fileKeyRecord.encryptedKey;
```

Alternatively, if backward compatibility requires the fallback, add a comment documenting exactly when each path is taken and add a try-catch with a targeted error message on the fallback path.

---

### [HIGH] H-03: Permission Downgrade Does Not Invalidate Cached Share Keys

**Location:** `apps/api/src/shares/shares.service.ts:348-376` (updatePermission) and `apps/web/src/hooks/useSharedNavigation.ts:160-172` (shareKeysCache)

**Issue:**
When the owner downgrades a share from write to read:

1. The server sets `permission = 'read'` and `encrypted_ipns_key = NULL` on the Share record
2. The server immediately rejects future publishes (via `findActiveWriteShare` returning null)
3. BUT: the `file-ipns` entries in `share_keys` are NOT deleted
4. The client caches share keys with a 60-second TTL (`SHARE_KEYS_CACHE_TTL`)

This means:

- The recipient retains all `file-ipns` keys in the database even after downgrade
- The recipient can still unwrap file IPNS private keys and sign file metadata updates
- While the **folder** IPNS publish will be rejected (server checks share permission), **per-file** IPNS records use their own IPNS names which may not be subject to the same authorization check

The per-file IPNS publish goes through the same `publishRecord` endpoint. The `file-ipns` keypair belongs to a different IPNS name than the folder share's `ipnsName`. When the recipient publishes a file IPNS update, the server checks `getFolderIpns(userId, ipnsName)` for the **file's** IPNS name. If the file was created by the recipient, the `folder_ipns` row was created with the recipient's userId, so they can continue publishing even after revocation.

Actually -- looking more carefully at the code: when a write-share recipient uploads a file (line 888-895), the file's IPNS record is published via `batchPublishIpnsRecords`. This creates a new `folder_ipns` row with `userId = recipientUserId` (since that is the authenticated user). After permission downgrade, the recipient still owns this `folder_ipns` row and can continue modifying the file's IPNS metadata indefinitely.

**Impact:**
A downgraded recipient can continue modifying individual files' metadata (changing CID pointers, file keys, etc.) even after their write access is revoked. This is limited to files with IPNS records created by the recipient, but it breaks the revocation guarantee.

**Recommendation:**

1. On permission downgrade, delete `file-ipns` entries from `share_keys` for this share
2. Consider transferring ownership of file IPNS records created by write-share recipients to the folder owner (so the owner's userId is on the `folder_ipns` row)
3. Short-term: in the new-entry path of `upsertFolderIpns` (line 253), when creating a file IPNS record, if the user is a write-share recipient, create the row under the **owner's** userId (same pattern as the existing entry path at line 233)

---

## Medium Priority Issues

### [MEDIUM] M-01: No Server-Side Validation That `encryptedIpnsKey` Is Actually an ECIES Ciphertext

**Location:** `apps/api/src/shares/dto/create-share.dto.ts:97-106`

**Code:**

```typescript
@IsString()
@Matches(/^[0-9a-fA-F]+$/, { message: 'encryptedIpnsKey must be a hex string' })
@MinLength(2)
@MaxLength(2048)
@IsOptional()
encryptedIpnsKey?: string;
```

**Issue:**
The validation only checks that the value is a hex string between 2 and 2048 characters. There is no check that the hex decodes to a valid ECIES ciphertext. A malicious sharer could store arbitrary data in this field. While the server is zero-knowledge and cannot validate the plaintext, it could validate:

1. Minimum expected ECIES ciphertext length (ECIES for a 32-byte key produces ~113 bytes of ciphertext minimum)
2. Maximum reasonable length

The current `MinLength(2)` accepts a single byte of hex, which cannot be a valid ECIES ciphertext. This same issue applies to `encryptedKey` with `MinLength(2)`.

**Impact:**
Low direct impact (server is zero-knowledge). A malicious owner could share garbage IPNS keys, but this only harms the recipient (who would get a decryption error). The real risk is storing unnecessarily large payloads (up to 2048 hex chars = 1024 bytes) or using the field for data exfiltration.

**Recommendation:**
Tighten the minimum length to match the minimum ECIES ciphertext size:

```typescript
@MinLength(200) // ECIES for 32-byte Ed25519 key produces ~226 hex chars minimum
@MaxLength(512) // Reasonable upper bound for ECIES wrapping a 32-byte key
```

---

### [MEDIUM] M-02: `addShareKeys` Authorization Allows Write-Recipient to Overwrite Existing Keys

**Location:** `apps/api/src/shares/shares.service.ts:188-226`

**Code:**

```typescript
const isWriteRecipient =
  share.recipientId === callerId && share.permission === 'write' && !share.revokedAt;

if (!isSharer && !isWriteRecipient) {
  throw new ForbiddenException('Only the sharer or write-share recipient can add keys');
}

// Upsert: insert or update encrypted_key for each itemId
for (const entry of dto.keys) {
  const existing = await this.shareKeyRepo.findOne({
    where: { shareId, keyType: entry.keyType, itemId: entry.itemId },
  });
  if (existing) {
    existing.encryptedKey = Buffer.from(entry.encryptedKey, 'hex');
    await this.shareKeyRepo.save(existing);
  }
}
```

**Issue:**
A write-share recipient can overwrite **any** existing `share_keys` entry for their share, including keys that were originally set by the owner. This means a malicious recipient could:

1. Replace a `file` key entry with garbage, preventing themselves from reading a file (low impact -- they harm only themselves)
2. Replace a `folder` key entry with garbage, preventing themselves from navigating subfolders (low impact)
3. However, combined with the fact that the recipient uses these keys for their own access, this is mostly self-sabotage

The more concerning scenario: if the system ever allows **other** write-share recipients to read from the same `share_keys` (e.g., in a future multi-recipient write model), one recipient could sabotage another's access.

**Impact:**
Currently low (recipient can only sabotage their own access). Increases to high if the sharing model evolves to have multiple recipients sharing the same `share_keys` entries.

**Recommendation:**
Add keyType-based authorization: write-share recipients should only be able to add/update `file` and `file-ipns` key types for items they created:

```typescript
if (isWriteRecipient) {
  // Write recipients can only add file/file-ipns keys, not folder keys
  const invalidTypes = dto.keys.filter((k) => k.keyType === 'folder');
  if (invalidTypes.length > 0) {
    throw new ForbiddenException('Write-share recipients cannot modify folder keys');
  }
}
```

---

### [MEDIUM] M-03: Fire-and-Forget `addShareKeys` in Upload Can Silently Lose Recipient's File Access

**Location:** `apps/web/src/hooks/useSharedNavigation.ts:931-944`

**Code:**

```typescript
await addShareKeys(currentShareId!, [
  {
    keyType: 'file',
    itemId: fileId,
    encryptedKey: bytesToHex(recipientWrappedFileKey),
  },
  {
    keyType: 'file-ipns',
    itemId: fileId,
    encryptedKey: bytesToHex(recipientWrappedIpnsKey),
  },
]).catch((err) => {
  console.warn('[share] Failed to add share_key for uploaded file:', err);
});
```

**Issue:**
When a write-share recipient uploads a file, the share_key entries are added as a fire-and-forget operation with only a `console.warn` on failure. If this call fails (network error, server error, race condition), the file is added to the folder metadata but the recipient has no `share_keys` entry for it. This means:

1. The recipient cannot download the file they just uploaded (the fallback to `fileMeta.fileKeyEncrypted` fails because that is wrapped with the owner's key)
2. The recipient cannot update the file later (no `file-ipns` key)
3. The file appears in the folder but is inaccessible to anyone except the owner

**Impact:**
Silent data access loss. The user successfully uploads a file but cannot read or modify it afterward. No error is shown to the user.

**Recommendation:**
Either:

1. Make this a non-fire-and-forget call -- if it fails, notify the user
2. Or add a retry mechanism with exponential backoff
3. At minimum, show a user-visible notification on failure:

```typescript
try {
  await addShareKeys(currentShareId!, [
    /* ... */
  ]);
} catch (err) {
  console.warn('[share] Failed to add share_key for uploaded file:', err);
  setError('File uploaded but access keys could not be saved. Please re-upload.');
}
```

---

### [MEDIUM] M-04: Polling Checks In-Memory Store Instead of Re-Fetching Shares from API

**Location:** `apps/web/src/hooks/useSharedNavigation.ts:1351-1368`

**Code:**

```typescript
pollIntervalRef.current = setInterval(async () => {
  try {
    // Re-fetch received shares to detect permission changes
    const shares = useShareStore.getState().receivedShares;
    const currentShare = shares.find((s) => s.shareId === currentShareId);

    // Check for silent revocation
    if (currentShare && currentShare.permission !== 'write') {
      handleRevocation(false);
      clearPolling();
      return;
    }
    // ...
```

**Issue:**
The comment says "Re-fetch received shares to detect permission changes" but the code reads from the **in-memory store** (`useShareStore.getState().receivedShares`). The store is only updated when:

1. The component mounts and loads shares
2. The user manually navigates back to the share list

There is no periodic API call to refresh the share records. This means the polling will **never** detect a permission downgrade until the user navigates away and back. The "silent revocation" feature described in the design docs does not actually work.

**Impact:**
A downgraded recipient continues to see write controls and can attempt (and fail with 403) write operations until they navigate away. The stated design goal of "silent downgrade on next sync poll" is not met.

**Recommendation:**
Periodically re-fetch the share record from the API during polling:

```typescript
pollIntervalRef.current = setInterval(async () => {
  try {
    // Actually re-fetch from API to detect permission changes
    const { shares } = await fetchReceivedShares(1, 0);
    // Or better: fetch just this specific share
    const freshShares = useShareStore.getState().receivedShares;
    // ... re-fetch logic
  }
});
```

Or add a lighter-weight API endpoint to check a single share's permission status.

---

## Low Priority Issues

### [LOW] L-01: `updatePermission` Does Not Check if Share Is Already Revoked

**Location:** `apps/api/src/shares/shares.service.ts:348-376`

**Code:**

```typescript
async updatePermission(
  shareId: string, sharerId: string,
  permission: 'read' | 'write', encryptedIpnsKey?: string
): Promise<void> {
  const share = await this.shareRepo.findOne({ where: { id: shareId } });
  // ...
  if (share.sharerId !== sharerId) {
    throw new ForbiddenException('Only the sharer can change permission');
  }
  // No check for share.revokedAt
```

**Issue:**
The method does not check if the share has been revoked (`revokedAt !== null`). This allows a sharer to upgrade a revoked share to write permission, which would give the recipient the IPNS key for a folder they should no longer have access to. While `findActiveWriteShare` correctly filters by `revokedAt: IsNull()`, the `updatePermission` path does not verify this.

**Recommendation:**

```typescript
if (share.revokedAt) {
  throw new ConflictException('Cannot change permission on a revoked share');
}
```

---

### [LOW] L-02: `resolvedSequenceNumber` Type Mismatch in `refreshFolderContents`

**Location:** `apps/web/src/hooks/useSharedNavigation.ts:218-228`

**Code:**

```typescript
const resolved = await resolveIpnsRecord(folderIpnsName);
// ...
setCurrentSequenceNumber(resolved.sequenceNumber);
```

**Issue:**
The `resolveIpnsRecord` returns `sequenceNumber` as a type that may be `string | bigint` depending on the source (DB cache returns string, network returns parsed bigint). The state is typed as `bigint | null`. If a string arrives here, the comparison `currentSequenceNumber ?? 0n` in write operations would produce incorrect results due to type coercion, potentially skipping conflict detection.

**Recommendation:**
Ensure consistent type coercion:

```typescript
setCurrentSequenceNumber(BigInt(resolved.sequenceNumber));
```

---

### [LOW] L-03: Missing Rate Limiting on Permission Toggle Endpoint

**Location:** `apps/api/src/shares/shares.controller.ts:253-277`

**Issue:**
The `PATCH :shareId/permission` endpoint uses the same `ThrottlerGuard` as other endpoints but has no additional rate limiting. An automated script could rapidly toggle permission between read and write, causing:

1. Unnecessary DB writes
2. The recipient's UI flickering between states
3. If lazy IPNS key rotation is triggered on each downgrade, resource waste

**Recommendation:**
Consider adding a per-share cooldown period for permission changes (e.g., no more than 1 change per minute per share), or at minimum verify this is covered by the existing throttle configuration.

---

## Positive Findings (Things Done Well)

### P-01: Correct IPNS Key Zeroing Pattern

Throughout `useSharedNavigation.ts`, IPNS private keys are properly zeroed after use:

- `ipnsPrivateKeyRef.current.fill(0)` on unmount (line 293)
- `zeroIpnsKey()` on navigation away (line 505)
- `ipnsKeypair.privateKey.fill(0)` after file upload (line 946)
- `keypair.privateKey.fill(0)` after folder creation (line 1070)
- File keys zeroed in finally blocks (line 949, 1069, 1267)

### P-02: Correct Authorization Model in `findActiveWriteShare`

The server-side authorization check (`findActiveWriteShare`) correctly filters by all four conditions:

- `recipientId` matches the authenticated user
- `ipnsName` matches the target IPNS name
- `permission === 'write'`
- `revokedAt: IsNull()`

This ensures revoked or read-only shares cannot publish.

### P-03: Correct TEE Enrollment UserId

The IPNS service correctly uses `existing.userId` (the FolderIpns owner) instead of the authenticated `userId` for TEE enrollment when a write-share recipient publishes. This ensures TEE republishing remains associated with the folder owner.

### P-04: IPNS Key Delivery via ECIES

The IPNS private key is correctly wrapped with the recipient's secp256k1 public key via ECIES before delivery. The server stores only the ciphertext (`encrypted_ipns_key`), maintaining zero-knowledge. The key is only unwrapped client-side.

### P-05: Safe Default Permission

The `permission` column defaults to `'read'`, ensuring all existing shares and new shares without explicit permission specification remain read-only. The UI defaults to `[ READ-ONLY ]` selected.

### P-06: Dual-Key Wrapping for Files Uploaded by Recipients

When a write-share recipient uploads a file (line 834-944), the file key is correctly wrapped with **both**:

- The owner's public key (for `fileKeyEncrypted` in FileMetadata -- owner can access)
- The recipient's public key (for `share_keys` entry -- recipient can access)

This ensures both parties can decrypt the file.

### P-07: Server-Side Sequence Number Coordination

The write-share architecture correctly routes all publishes through the owner's single `FolderIpns` row, maintaining sequence number coordination. The `expectedSequenceNumber` check prevents lost updates even with multiple concurrent writers.

---

## Test Cases

### Backend Tests

```typescript
describe('SharesService - Permission Management', () => {
  describe('Positive Cases', () => {
    it('upgrades a share from read to write with IPNS key', async () => {
      // Create share with permission='read', then updatePermission to 'write'
      // Verify: permission='write', encryptedIpnsKey is set
    });

    it('downgrades a share from write to read, clearing IPNS key', async () => {
      // Create write share, then updatePermission to 'read'
      // Verify: permission='read', encryptedIpnsKey=null
    });

    it('findActiveWriteShare returns share for write recipient', async () => {
      // Create write share
      // Verify: findActiveWriteShare returns the share
    });

    it('findActiveWriteShare returns null for read recipient', async () => {
      // Create read-only share
      // Verify: findActiveWriteShare returns null
    });
  });

  describe('Negative Cases', () => {
    it('rejects permission change by non-sharer', async () => {
      // Attempt updatePermission as recipient
      // Verify: ForbiddenException
    });

    it('rejects write upgrade without encryptedIpnsKey', async () => {
      // Attempt updatePermission('write') without IPNS key
      // Verify: BadRequestException
    });

    it('rejects addShareKeys from read-only recipient', async () => {
      // Create read-only share, attempt addShareKeys as recipient
      // Verify: ForbiddenException
    });
  });

  describe('Edge Cases', () => {
    it('allows addShareKeys from write-share recipient', async () => {
      // Create write share, addShareKeys as recipient
      // Verify: success
    });

    it('handles permission change on revoked share', async () => {
      // Create and revoke share, attempt updatePermission
      // Verify: should reject (see L-01)
    });

    it('findActiveWriteShare returns null for revoked write share', async () => {
      // Create write share, revoke it
      // Verify: findActiveWriteShare returns null
    });
  });
});

describe('IpnsService - Write-Share Authorization', () => {
  describe('Positive Cases', () => {
    it('allows write-share recipient to publish to shared IPNS name', async () => {
      // Create write share, attempt publishRecord as recipient
      // Verify: success, sequence number incremented on owner's row
    });
  });

  describe('Negative Cases', () => {
    it('rejects publish from read-only recipient', async () => {
      // Create read-only share, attempt publishRecord as recipient
      // Verify: ForbiddenException (or falls through to new-entry path, which is also wrong)
    });

    it('rejects publish from revoked write-share recipient', async () => {
      // Create write share, revoke, attempt publishRecord
      // Verify: rejected
    });
  });

  describe('Attack Scenarios', () => {
    it('prevents write-share recipient from overwriting TEE enrollment key', async () => {
      // Create write share, recipient publishes with encryptedIpnsPrivateKey
      // Verify: TEE key should NOT be updated (see H-01)
    });

    it('prevents unauthorized IPNS publish via ipnsName not covered by share', async () => {
      // Create write share for IPNS name A
      // Attempt publish to IPNS name B as recipient
      // Verify: rejected
    });
  });
});
```

### Frontend Tests

```typescript
describe('useSharedNavigation - Write Operations', () => {
  describe('Key Management', () => {
    it('unwraps IPNS private key for write shares', async () => {
      // Navigate to write-shared folder
      // Verify: ipnsPrivateKey is non-null
    });

    it('does not unwrap IPNS key for read-only shares', async () => {
      // Navigate to read-only shared folder
      // Verify: ipnsPrivateKey is null
    });

    it('zeros IPNS key on navigation away', async () => {
      // Navigate to write share, then navigate to root
      // Verify: ipnsPrivateKey ref zeroed
    });

    it('zeros all keys on component unmount', async () => {
      // Mount, navigate to share, unmount
      // Verify: all keys zeroed
    });
  });

  describe('Conflict Handling', () => {
    it('retries with fresh sequence number after 409', async () => {
      // Mock 409 on first attempt, success on retry
      // Verify: retry uses refreshed sequence number
    });

    it('detects 403 and transitions to read-only', async () => {
      // Mock 403 on write operation
      // Verify: permission becomes 'read', IPNS key zeroed
    });
  });

  describe('Subfolder Key Wrapping', () => {
    it('wraps subfolder keys with owner public key, not recipient', async () => {
      // Create subfolder as write-share recipient
      // Verify: FolderEntry keys are wrapped with owner's public key (see C-02)
    });
  });
});
```

---

## Recommendations (Prioritized)

1. **[CRITICAL] Fix stale closure in conflict retry** (C-01) -- Use refs alongside React state for values consumed in retry closures. This is the most impactful bug: multi-writer conflicts (the primary feature) will reliably fail.

2. **[CRITICAL] Fix subfolder key wrapping** (C-02) -- Wrap FolderEntry keys with owner's public key. Without this fix, subfolders created by recipients become inaccessible to the owner, causing permanent data loss.

3. **[HIGH] Block TEE enrollment data from write-share recipients** (H-01) -- Add a guard in `upsertFolderIpns` to prevent write-share recipients from modifying `encryptedIpnsPrivateKey` and `keyEpoch`.

4. **[HIGH] Fix file IPNS ownership model** (H-03) -- File IPNS records created by write-share recipients should be owned by the folder owner in `folder_ipns`, and `file-ipns` share_keys should be cleaned up on permission downgrade.

5. **[HIGH] Replace silent fallback with explicit error** (H-02) -- The `fileKeyRecord?.encryptedKey ?? fileMeta.fileKeyEncrypted` fallback masks the real issue and never succeeds for the share recipient.

6. **[MEDIUM] Fix polling to actually re-fetch share data from API** (M-04) -- Without this, the "silent revocation" feature does not work as designed.

7. **[MEDIUM] Make share_key creation non-fire-and-forget** (M-03) -- Or at minimum show a user notification on failure.

8. **[LOW] Add revocation check to updatePermission** (L-01) -- Prevent upgrading a revoked share.

---

**Report generated:** 2026-03-26
**Valid until:** Issues are addressed or architecture changes
