# Phase 14: User-to-User Sharing - Research

**Researched:** 2026-02-21
**Domain:** Client-side ECIES key re-wrapping, server-side share records, recipient browsing architecture
**Confidence:** HIGH (all components use existing, verified infrastructure)

## Summary

Phase 14 implements user-to-user sharing of encrypted folders and individual files while maintaining CipherBox's zero-knowledge guarantees. The core cryptographic operation -- ECIES re-wrapping -- is straightforward: the sharer decrypts a key with their private key and re-encrypts it with the recipient's public key, using the exact same `wrapKey()` / `unwrapKey()` functions already in `packages/crypto/src/ecies/`. No new crypto primitives are needed.

The architectural complexity lies in three areas: (1) designing the server-side share record storage that enables recipient discovery without leaking plaintext keys, (2) building the "Shared with me" browsing experience where recipients resolve the sharer's IPNS records using the sharer's folderKey/fileKey (re-wrapped for the recipient), and (3) implementing lazy key rotation on revocation. All three areas build on well-understood existing patterns in the codebase.

**Primary recommendation:** Implement sharing as a server-side share record table with ECIES-wrapped keys, a dedicated API module, and a new `~/shared` browsing section that reuses the existing folder/file resolution infrastructure but with a different key source (share record instead of parent metadata).

---

## 1. ECIES Re-Wrapping Protocol

### How It Works

The re-wrapping protocol is the cryptographic core of sharing. It requires NO new crypto primitives -- only the existing `wrapKey()` and `unwrapKey()` from `packages/crypto/src/ecies/`.

**Confidence: HIGH** -- verified against existing ECIES tests in `packages/crypto/src/__tests__/ecies.test.ts` and the `eciesjs` v0.4.16 library.

#### Folder Sharing Sequence

```
SHARER (Alice):
1. Has folderKey (decrypted in RAM, from parent metadata)
2. Has recipientPublicKey (pasted by user, validated as secp256k1 point)
3. Calls: wrappedForRecipient = await wrapKey(folderKey, recipientPublicKey)
4. Sends wrappedForRecipient + ipnsName to server as a share record

RECIPIENT (Bob):
1. Fetches share records from server: GET /shares/received
2. Gets wrappedForRecipient + ipnsName for each shared folder
3. Calls: folderKey = await unwrapKey(wrappedForRecipient, bobPrivateKey)
4. Resolves IPNS to get encrypted metadata CID
5. Decrypts metadata with folderKey
6. For each child: unwraps folderKeyEncrypted/fileKeyEncrypted with OWN privateKey?
   NO -- these are wrapped with Alice's publicKey. Bob needs a different approach.
```

#### Critical Design Point: Child Key Access

This is the most important architectural decision in the entire phase. There are two approaches:

**Approach A: Re-wrap all descendant keys (recursive)**

- Sharer must decrypt and re-wrap `folderKeyEncrypted` for every subfolder and `fileKeyEncrypted` for every file in the shared folder tree
- Pro: Recipient can browse the full tree identically to the owner
- Con: O(n) ECIES operations where n = total descendants. Expensive for large folders. Must be repeated for every new recipient. When files are added to a shared folder, sharer must re-wrap new keys for all recipients.

**Approach B: Share only the root folderKey, recipient uses it to access everything**

- Sharer re-wraps only the shared folder's `folderKey`
- Recipient decrypts folder metadata using `folderKey` (AES-256-GCM, same as owner does)
- For subfolders: `folderKeyEncrypted` in metadata is ECIES-wrapped with owner's publicKey -- recipient CANNOT unwrap these
- For files: `fileKeyEncrypted` in FileMetadata is ECIES-wrapped with owner's publicKey -- recipient CANNOT unwrap these

**Approach C (RECOMMENDED): Share folderKey, but also re-wrap subfolder keys and provide mechanism for file key access**

The existing metadata structure reveals the solution:

1. **FolderMetadata** is encrypted with `folderKey` (AES-256-GCM). Anyone with `folderKey` can decrypt it.
2. Inside decrypted metadata, `FolderEntry.folderKeyEncrypted` is ECIES-wrapped with owner's `publicKey`. Only the owner can unwrap.
3. Inside decrypted metadata, `FolderEntry.ipnsPrivateKeyEncrypted` is ECIES-wrapped with owner's `publicKey`. Only the owner can unwrap.
4. **FileMetadata** (per-file IPNS) is encrypted with the parent folder's `folderKey` (AES-256-GCM). Anyone with `folderKey` can decrypt it.
5. Inside decrypted FileMetadata, `fileKeyEncrypted` is ECIES-wrapped with owner's `publicKey`. Only the owner can unwrap.

So the access pattern for a recipient with only the shared `folderKey` is:

- **CAN** decrypt folder metadata (AES-GCM with folderKey) -- sees file names, subfolder names
- **CAN** decrypt file metadata (AES-GCM with parent folderKey) -- sees CID, fileIv, size, mimeType
- **CANNOT** unwrap `fileKeyEncrypted` -- it's ECIES-wrapped with owner's publicKey
- **CANNOT** unwrap subfolder `folderKeyEncrypted` -- same problem

This means **the sharer must also re-wrap the file keys and subfolder keys for the recipient**. But doing this at share-time for the entire tree is impractical.

#### Recommended Protocol: Dual-Wrapped Keys in Share Records

The share record stores re-wrapped keys alongside the standard owner-wrapped keys:

**For folder sharing:**

```
Share Record:
  - sharerPublicKey: "0x04..." (who shared)
  - recipientPublicKey: "0x04..." (who receives)
  - itemType: "folder"
  - ipnsName: "k51..." (folder's IPNS address)
  - folderKeyEncrypted: hex (folderKey wrapped with recipient's publicKey)
  - createdAt: timestamp
```

The recipient gets the `folderKey`, which lets them decrypt folder metadata and file metadata (both AES-GCM). But for `fileKeyEncrypted` in each FileMetadata, the recipient still cannot decrypt because it's wrapped with the owner's publicKey.

**Solution: Re-wrap file keys at access time (lazy re-wrapping via the sharer)**

This is actually not needed! Let me re-examine the metadata:

Looking at `FileMetadata` in `packages/crypto/src/file/types.ts`:

```typescript
fileKeyEncrypted: string; // ECIES-wrapped with owner's publicKey
```

And at `FolderEntry` in `packages/crypto/src/folder/types.ts`:

```typescript
folderKeyEncrypted: string; // ECIES-wrapped with owner's publicKey
ipnsPrivateKeyEncrypted: string; // ECIES-wrapped with owner's publicKey
```

These are wrapped with the OWNER's key. The recipient cannot unwrap them.

**Final Recommended Approach: Share the folderKey AND the sharer also stores all necessary file keys re-wrapped for the recipient**

Actually, the simplest correct approach is:

1. **For the shared folder itself**: re-wrap `folderKey` with recipient's publicKey (1 ECIES operation). Store in share record.
2. **For files in that folder**: The recipient has `folderKey`, so they can decrypt the FileMetadata (AES-GCM). The `fileKeyEncrypted` inside FileMetadata is wrapped with owner's publicKey. The sharer must ALSO re-wrap each `fileKey` with recipient's publicKey and include these in the share record (or metadata).

But this is the recursive problem again. If the folder has 100 files, we need 100 re-wrapping operations at share time, and we need to re-wrap whenever a new file is added.

**SIMPLEST CORRECT APPROACH (RECOMMENDED):**

Re-examine the encryption hierarchy:

- File CONTENT is encrypted with `fileKey` (AES-256-GCM)
- `fileKey` is ECIES-wrapped with owner's publicKey, stored in FileMetadata
- FileMetadata is encrypted with parent `folderKey` (AES-256-GCM)

If the sharer re-wraps `fileKey` values for each file at share-time, the recipient can download and decrypt file content. But this doesn't scale for evolving folders.

**THE REAL SOLUTION: Have the sharer re-wrap keys on each modification.**

When the sharer modifies the shared folder (adds a file, etc.):

1. The normal flow already calls `wrapKey(fileKey, ownerPublicKey)` to create `fileKeyEncrypted`
2. For each share recipient, ALSO call `wrapKey(fileKey, recipientPublicKey)` and store the result

**Where to store the recipient-wrapped keys?** Two options:

**Option 1: In the metadata itself** -- Add optional fields like `sharedFileKeys: { [recipientPubKey]: hexWrappedKey }` to FileMetadata. This leaks sharing metadata in the encrypted blob and requires metadata schema changes.

**Option 2: In the server-side share records** -- Store re-wrapped keys in the database, indexed by (ipnsName + fileId + recipientPublicKey). The recipient fetches their re-wrapped keys from the API alongside the IPNS-resolved metadata.

**Option 2 is recommended** because:

- No metadata schema changes
- No impact on the encrypted IPFS blobs
- Server already mediates all access (zero-knowledge: sees only ciphertexts)
- Easy to revoke (delete the records)

### Detailed Re-Wrapping Protocol

```
SHARING A FOLDER:
1. Sharer opens share dialog for folder F with folderKey FK
2. Sharer pastes recipient's publicKey RPK
3. Client validates RPK is a registered CipherBox user (API check)
4. Client computes: wrappedFK = wrapKey(FK, RPK)
5. Client traverses folder F's children:
   a. For each file: resolve FileMetadata, unwrap fileKeyEncrypted -> fileKey
      Compute: wrappedFileKey = wrapKey(fileKey, RPK)
   b. For each subfolder: unwrap folderKeyEncrypted -> subfolderKey
      Compute: wrappedSubfolderKey = wrapKey(subfolderKey, RPK)
      Recursively process subfolder's children
6. Client sends batch share record to API:
   POST /shares {
     recipientPublicKey: RPK,
     items: [
       { type: 'folder', ipnsName, folderKeyEncrypted: hex(wrappedFK) },
       { type: 'file-key', fileId, fileKeyEncrypted: hex(wrappedFileKey) },
       { type: 'folder-key', folderId, folderKeyEncrypted: hex(wrappedSubfolderKey) },
       ...
     ]
   }
7. Server stores share records. Server never sees plaintext keys.

ADDING A FILE TO A SHARED FOLDER (sharer's normal flow, extended):
1. Normal flow: encrypt file, wrap fileKey with owner's publicKey, publish
2. Additional: for each recipient in share records for this folder:
   a. Fetch recipient's publicKey from share records
   b. Compute: wrappedFileKey = wrapKey(fileKey, recipientPublicKey)
   c. POST /shares/keys { recipientPublicKey, fileId, fileKeyEncrypted }

RECIPIENT BROWSING SHARED FOLDER:
1. GET /shares/received -> list of shared items
2. For each shared folder:
   a. unwrapKey(folderKeyEncrypted, recipientPrivateKey) -> folderKey
   b. Resolve folder IPNS -> get encrypted metadata
   c. Decrypt metadata with folderKey (AES-GCM) -> see files and subfolders
   d. For each file to download:
      - GET /shares/keys?fileId=xxx -> get recipient-wrapped fileKeyEncrypted
      - unwrapKey(fileKeyEncrypted, recipientPrivateKey) -> fileKey
      - Fetch encrypted content from IPFS, decrypt with fileKey
   e. For each subfolder to browse:
      - GET /shares/keys?folderId=xxx -> get recipient-wrapped folderKeyEncrypted
      - unwrapKey(folderKeyEncrypted, recipientPrivateKey) -> subfolderKey
      - Resolve subfolder IPNS, decrypt with subfolderKey
```

### Simplification: Flat Key Table

Rather than nesting share records, use a flat key table:

```
share_keys table:
  id, share_id, item_type ('folder'|'file'), item_id,
  encrypted_key (ECIES-wrapped for recipient), created_at
```

Where `item_id` is either the folder UUID or file UUID, and `encrypted_key` is the relevant key (folderKey or fileKey) wrapped with the recipient's publicKey.

### Performance Analysis

ECIES wrapping with `eciesjs` v0.4.16 (secp256k1):

- Each `wrapKey()` call: ~1-3ms (dominated by secp256k1 point multiplication)
- Sharing a folder with 100 files + 5 subfolders: ~105 wrapping operations = ~100-300ms
- Sharing a folder with 1000 files: ~1000 operations = ~1-3 seconds
- This is acceptable for a one-time share operation triggered by user action

### Test Vector for Correctness Verification

```typescript
// Test: Re-wrapping preserves the original key
it('re-wrapped key decrypts to same value', async () => {
  const alice = generateTestKeypair();
  const bob = generateTestKeypair();

  // Alice wraps a file key with her own public key (normal flow)
  const fileKey = generateRandomBytes(32);
  const wrappedForAlice = await wrapKey(fileKey, alice.publicKey);

  // Alice unwraps and re-wraps for Bob
  const unwrappedKey = await unwrapKey(wrappedForAlice, alice.privateKey);
  const wrappedForBob = await wrapKey(unwrappedKey, bob.publicKey);

  // Bob unwraps with his private key
  const bobsKey = await unwrapKey(wrappedForBob, bob.privateKey);

  // Both should get the same original key
  expect(bobsKey).toEqual(fileKey);
  expect(unwrappedKey).toEqual(fileKey);
});
```

---

## 2. Share Record Storage Architecture

### Recommended Schema

**Confidence: HIGH** -- follows existing entity patterns from `apps/api/src/`.

Two tables: one for the share relationship, one for the re-wrapped keys.

```sql
-- Share relationships: who shared what with whom
CREATE TABLE shares (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sharer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  item_type VARCHAR(10) NOT NULL CHECK (item_type IN ('folder', 'file')),
  -- For folders: the folder's IPNS name. For files: the file's IPNS name.
  ipns_name VARCHAR(255) NOT NULL,
  -- The shared item's key wrapped with recipient's publicKey
  -- For folders: folderKey. For files: parent's folderKey (for metadata decryption).
  encrypted_key BYTEA NOT NULL,
  -- Recipient has hidden/dismissed this share
  hidden_by_recipient BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(sharer_id, recipient_id, ipns_name)
);

CREATE INDEX idx_shares_recipient ON shares(recipient_id) WHERE hidden_by_recipient = FALSE;
CREATE INDEX idx_shares_sharer ON shares(sharer_id);
CREATE INDEX idx_shares_ipns ON shares(ipns_name);

-- Re-wrapped descendant keys for shared folders
-- When sharing a folder, all child file keys and subfolder keys are re-wrapped
CREATE TABLE share_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  share_id UUID NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  -- 'file' for fileKey, 'folder' for subfolderKey
  key_type VARCHAR(10) NOT NULL CHECK (key_type IN ('file', 'folder')),
  -- UUID of the file or subfolder
  item_id VARCHAR(255) NOT NULL,
  -- The key wrapped with recipient's publicKey
  encrypted_key BYTEA NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(share_id, key_type, item_id)
);

CREATE INDEX idx_share_keys_share ON share_keys(share_id);
CREATE INDEX idx_share_keys_item ON share_keys(item_id);
```

### NestJS Entity Pattern

Following existing entities like `FolderIpns` (`apps/api/src/ipns/entities/folder-ipns.entity.ts`):

```typescript
@Entity('shares')
@Unique(['sharerId', 'recipientId', 'ipnsName'])
export class Share {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid', name: 'sharer_id' })
  sharerId!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'sharer_id' })
  sharer!: User;

  @Column({ type: 'uuid', name: 'recipient_id' })
  recipientId!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'recipient_id' })
  recipient!: User;

  @Column({ type: 'varchar', length: 10, name: 'item_type' })
  itemType!: 'folder' | 'file';

  @Column({ type: 'varchar', length: 255, name: 'ipns_name' })
  ipnsName!: string;

  @Column({ type: 'bytea', name: 'encrypted_key' })
  encryptedKey!: Buffer;

  @Column({ type: 'boolean', name: 'hidden_by_recipient', default: false })
  hiddenByRecipient!: boolean;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt!: Date;
}
```

### API Endpoints

```
POST /shares                    -- Create a share (sharer sends re-wrapped keys)
GET  /shares/received           -- List shares received by current user
GET  /shares/sent               -- List shares sent by current user
GET  /shares/:shareId/keys      -- Get re-wrapped keys for a specific share
POST /shares/:shareId/keys      -- Add re-wrapped keys (when sharer adds files)
DELETE /shares/:shareId         -- Revoke a share (sharer only)
PATCH /shares/:shareId/hide     -- Hide a share (recipient only)
GET  /users/lookup?publicKey=X  -- Verify publicKey belongs to registered user
```

### Zero-Knowledge Guarantees

The server stores:

- `encrypted_key`: ECIES ciphertext (opaque bytes, ~129 bytes for a 32-byte key)
- `ipns_name`: public identifier (already known by server from IPNS publishing)
- User IDs: already in the system

The server NEVER sees:

- Plaintext `folderKey` or `fileKey`
- File names (encrypted in IPNS metadata)
- File content (encrypted on IPFS)

---

## 3. Recipient Discovery & Resolution

### How Recipients Find Shared Items

**Confidence: HIGH** -- uses existing API polling pattern.

Recipients discover shared items by polling a dedicated API endpoint:

```
GET /shares/received
Response: [
  {
    shareId: "uuid",
    sharerPublicKey: "0x04...",
    itemType: "folder",
    ipnsName: "k51...",
    encryptedKey: "hex...",
    createdAt: "2026-02-21T..."
  },
  ...
]
```

**Polling strategy:** Same 30-second interval as existing sync (`useSyncPolling`). A separate poll for shares (or combined into the existing sync cycle). Since shares don't change frequently, polling is adequate.

**Alternative considered: Server-sent events / WebSocket.** Rejected -- CipherBox uses no push infrastructure anywhere (per CONTEXT.md: "sync via IPNS polling, no push infrastructure"). Adding SSE for sharing only would add architectural inconsistency.

### Public Key Validation

When the sharer pastes a recipient's public key:

1. Client validates format: 65 bytes, 0x04 prefix, valid secp256k1 curve point (existing validation in `wrapKey()`)
2. Client calls API: `GET /users/lookup?publicKey=0x04...`
3. Server checks: does a user with this publicKey exist?
4. If no: error "User not found. They must have a CipherBox account."
5. If yes: returns `{ userId, publicKey }` -- server resolves publicKey to userId for the share record

This is secure because `publicKey` is already public data stored in the `users` table.

---

## 4. Lazy Key Rotation Protocol

### How Lazy Rotation Works on Revocation

**Confidence: MEDIUM** -- protocol is well-defined but involves subtle race conditions that need careful implementation.

Per CONTEXT.md decision: "revoking a share removes the recipient's access record but does NOT immediately rotate the folderKey. Key rotation happens on next folder modification."

```
REVOCATION:
1. Sharer clicks "Revoke" on a recipient
2. Client calls: DELETE /shares/:shareId
3. Server deletes the share record and all associated share_keys records
4. Revoked recipient can still technically resolve the IPNS and decrypt metadata
   (they still know the old folderKey from when they received it)
5. But they can no longer fetch re-wrapped file keys from the API
6. AND on the sharer's next folder modification, the key rotates

KEY ROTATION (on next modification):
1. Sharer adds/modifies/deletes a file in the shared folder
2. Client detects this folder has had a revocation since last rotation
   (server endpoint: GET /shares/pending-rotations)
3. Client generates: newFolderKey = generateRandomBytes(32)
4. Client re-encrypts folder metadata with newFolderKey
5. Client re-wraps newFolderKey with owner's publicKey (for parent metadata)
6. Client re-wraps newFolderKey with each REMAINING recipient's publicKey
7. Client updates parent metadata with new folderKeyEncrypted
8. Client publishes updated IPNS record
9. Server updates share records with new encrypted_key for remaining recipients
10. Server marks rotation as complete

WHAT ROTATES:
- folderKey (the AES-256 key used to encrypt/decrypt folder metadata)
- All child entries' folderKeyEncrypted / ipnsPrivateKeyEncrypted in the metadata
  (these need to be re-wrapped with owner's publicKey using the old key to decrypt first)
- File keys do NOT rotate -- they are per-file and independent
  (the revoked user already had those file keys, but they can't get NEW file keys)

WHAT DOESN'T CHANGE:
- IPNS name (same folder, same address)
- IPNS private key (same signing key, owner keeps it)
- File CIDs (file content doesn't change)
- File keys (individual file decryption keys stay the same)
```

### Race Condition: Revoked User Reads Before Rotation

Between revocation and key rotation, the revoked user still has the old `folderKey` and could resolve IPNS to read current metadata. This is explicitly accepted in the CONTEXT.md decision ("lazy rotation"). The security model is:

1. Revoked user sees the folder state AS OF their last access
2. New files added after rotation use a new `folderKey` they don't have
3. Old files are still decryptable (they had the file keys) -- this is inherent to any read-only sharing system

### Tracking Pending Rotations

Add a flag to the share record or a separate table:

```sql
-- Option: Add to shares table
ALTER TABLE shares ADD COLUMN revoked_at TIMESTAMP;
-- Instead of DELETE, SET revoked_at = NOW()
-- On next modification, client queries for revoked shares, does rotation, then DELETEs

-- Or: Separate tracking
CREATE TABLE pending_rotations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  folder_ipns_name VARCHAR(255) NOT NULL,
  sharer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  revoked_share_id UUID NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(folder_ipns_name, revoked_share_id)
);
```

**Recommendation:** Use soft-delete on the shares table (set `revoked_at`). When the sharer next modifies the folder, the client queries for revoked shares, performs key rotation, re-wraps for remaining recipients, and hard-deletes the revoked records.

---

## 5. File-Level vs Folder-Level Sharing

### File-Level Sharing

**Confidence: HIGH** -- per-file IPNS from Phase 12.6 makes this architecturally clean.

Per CONTEXT.md: "Both folder-level AND file-level sharing supported (per-file IPNS from Phase 12.6 makes this architecturally possible)"

For file sharing, the protocol is simpler than folder sharing:

```
SHARING A FILE:
1. Sharer selects file, opens share dialog
2. Sharer resolves file's FileMetadata from its IPNS record
3. Sharer decrypts FileMetadata with parent folderKey (AES-GCM)
4. Sharer unwraps fileKeyEncrypted with own privateKey -> fileKey
5. Sharer wraps fileKey with recipientPublicKey: wrappedFileKey = wrapKey(fileKey, RPK)
6. Also wraps parent folderKey with RPK (needed to decrypt FileMetadata):
   wrappedFolderKey = wrapKey(parentFolderKey, RPK)
7. Creates share record:
   POST /shares {
     recipientPublicKey: RPK,
     itemType: 'file',
     ipnsName: fileMetaIpnsName,
     encryptedKey: wrappedFolderKey,  // For metadata decryption
     fileKeys: [{ fileId, encryptedKey: wrappedFileKey }]
   }

RECIPIENT DOWNLOADING SHARED FILE:
1. GET /shares/received -> finds shared file
2. Unwrap encryptedKey (folderKey) with own privateKey
3. Resolve file's IPNS -> get FileMetadata CID
4. Fetch and decrypt FileMetadata with folderKey
5. Get wrappedFileKey from share_keys: GET /shares/:id/keys?fileId=xxx
6. Unwrap fileKey with own privateKey
7. Fetch encrypted content from IPFS, decrypt with fileKey + fileIv
```

### Key Difference: File Share vs Folder Share

| Aspect                 | Folder Share                           | File Share                                |
| ---------------------- | -------------------------------------- | ----------------------------------------- |
| Re-wrapped key         | folderKey                              | parent folderKey + individual fileKey     |
| Recipient sees         | Folder contents (all files/subfolders) | Single file only                          |
| IPNS resolution        | Folder's IPNS name                     | File's IPNS name                          |
| Key rotation on revoke | New folderKey needed                   | No rotation (per-file key is independent) |
| New files auto-shared  | Yes (if sharer re-wraps)               | N/A (single file)                         |

---

## 6. "Shared with me" Browsing Architecture

### Navigation Model

**Confidence: HIGH** -- follows existing breadcrumb navigation pattern.

Per CONTEXT.md: "`Shared with me` is a separate top-level section, navigated via breadcrumb path `~/shared`"

The `~/shared` section operates as a virtual folder that doesn't correspond to any IPNS record. Its children are the top-level shared items (folders and files) fetched from the API.

```
Route: /shared                    -> ~/shared (list of all shared items)
Route: /shared/:shareId           -> ~/shared/documents/ (browsing a shared folder)
Route: /shared/:shareId/:folderId -> ~/shared/documents/subfolder/ (nested)
```

### Store Architecture

A new Zustand store `share.store.ts` manages shared items:

```typescript
type SharedItem = {
  shareId: string;
  sharerPublicKey: string;
  itemType: 'folder' | 'file';
  ipnsName: string;
  encryptedKey: string; // hex-encoded, ECIES-wrapped for recipient
  createdAt: string;
  // Resolved fields (after client decryption):
  name?: string; // Only known after resolving IPNS metadata
};

type SharedFolderNode = {
  shareId: string;
  folderId: string; // synthetic ID for navigation
  folderKey: Uint8Array;
  ipnsName: string;
  children: FolderChild[];
  isLoaded: boolean;
  name: string;
  parentId: string | null; // null for top-level shared folder
};

type ShareState = {
  receivedShares: SharedItem[];
  sharedFolders: Record<string, SharedFolderNode>;
  isLoading: boolean;
  // ... actions
};
```

### Browsing Flow

```
1. User navigates to ~/shared
2. Client fetches: GET /shares/received
3. For each shared folder:
   a. Unwrap folderKey: unwrapKey(encryptedKey, privateKey)
   b. Resolve IPNS: GET /ipns/resolve?ipnsName=xxx
   c. Fetch and decrypt metadata: folderKey decrypts the folder metadata
   d. Display folder name (from decrypted metadata -- wait, folder name is
      in PARENT metadata, not the folder's own metadata)
```

**Important:** Folder names are stored in the PARENT's metadata as `FolderEntry.name`. The folder's own metadata (`FolderMetadata`) contains only `version` and `children`. So the sharer must include the item name in the share record, OR the recipient resolves it from context.

**Recommendation:** Include the item name (encrypted) in the share record:

```sql
ALTER TABLE shares ADD COLUMN item_name_encrypted BYTEA;
-- AES-GCM encrypted item name, encrypted with a key derived from the share's encryptedKey
```

Actually, simpler: just include the plaintext name in the share record. The server already knows the user IDs involved; the item name isn't a significant privacy leak compared to that. But to maintain zero-knowledge discipline, encrypt the name or use a display name the sharer provides.

**Simplest approach:** The share record includes the shared item's display name as a plaintext field. The server sees this name, but it sees user IDs anyway, so the privacy impact is minimal. If this is unacceptable, encrypt the name with the recipient's publicKey.

**Recommendation:** Include item name as plaintext in share record for simplicity. The name is visible to the server but does not compromise file content security.

### Read-Only Enforcement

Per CONTEXT.md: "No upload/new-folder/refresh buttons when browsing shared content (read-only)"

When in `~/shared` context:

- Hide upload button, new folder button
- Disable rename, move, delete in context menu
- Show `[RO]` badge on items
- Disable drag-and-drop upload
- Context menu shows only: Download, Preview, Details

### Differences from Own Files Browsing

| Aspect          | Own Files                       | Shared Files                               |
| --------------- | ------------------------------- | ------------------------------------------ |
| Key source      | Parent metadata (ECIES-wrapped) | Share record (ECIES-wrapped for recipient) |
| IPNS signing    | User's IPNS private key         | N/A (read-only, no publishing)             |
| Upload/modify   | Full CRUD                       | Read-only (download/preview only)          |
| Breadcrumb root | `~/root`                        | `~/shared`                                 |
| Sync polling    | Root IPNS polling               | Per-share IPNS polling (or on-navigate)    |
| Context menu    | Full actions                    | Download, Preview, Details only            |

---

## 7. Version History in Shared Context

### Should Recipients See Version History?

**Confidence: MEDIUM** -- this is noted as an open question in STATE.md.

FileMetadata includes an optional `versions: VersionEntry[]` array (added in Phase 13). Each VersionEntry contains `fileKeyEncrypted` (ECIES-wrapped with owner's publicKey).

If the sharer includes re-wrapped keys for ALL version entries in the share record, the recipient can see and download old versions. This is:

- **More re-wrapping work:** For a file with 10 versions, that's 10 additional ECIES operations per recipient
- **Privacy concern:** The sharer might want to share only the current version, not the full history
- **Complexity:** Must track version key re-wrapping as versions are created

**Recommendation:** For Phase 14, **do NOT share version history**. Recipients see only the current version. The `versions` array in FileMetadata is visible to recipients (they can decrypt FileMetadata with folderKey), but they cannot decrypt old version content because they don't have the old fileKeys.

This is a clean default that can be upgraded later if needed. The UI simply omits the version tab/panel when viewing shared files.

---

## 8. Desktop & TEE Implications

### Desktop FUSE Mount

**Confidence: HIGH** -- clearly deferred.

Per CONTEXT.md deferred ideas: Desktop FUSE implications are not mentioned in decisions, and the sharing feature is primarily a web UI feature for Phase 14. Shared folders should NOT appear in `~/CipherBox` FUSE mount.

Desktop support for shared folders would require the Rust FUSE implementation to understand share records, which is a separate phase.

### TEE Republishing for Shared IPNS Records

**Confidence: HIGH** -- no TEE changes needed.

Shared folders and files use the SHARER's IPNS records. The sharer's TEE republishing schedule already covers these IPNS records (they were enrolled when the sharer first published them). No additional TEE enrollment is needed for sharing.

Recipients do NOT own the IPNS private keys, so they cannot:

- Publish IPNS updates (read-only, by design)
- Enroll IPNS records for TEE republishing
- Sign IPNS records

This is correct behavior -- the sharer remains the sole authority over the IPNS records.

---

## 9. Don't Hand-Roll

Problems with existing solutions in the codebase:

| Problem                    | Don't Build        | Use Instead                                                     | Why                                                            |
| -------------------------- | ------------------ | --------------------------------------------------------------- | -------------------------------------------------------------- |
| ECIES key wrapping         | Custom ECIES       | `wrapKey()` / `unwrapKey()` from `packages/crypto/src/ecies/`   | Already tested, uses `eciesjs` v0.4.16, validates curve points |
| secp256k1 key validation   | Custom validation  | `ProjectivePoint.fromHex()` from `@noble/secp256k1`             | Already used in `wrapKey()`, handles all edge cases            |
| IPNS resolution            | Custom resolver    | `resolveIpnsRecord()` from `services/ipns.service.ts`           | Already handles retries, DB fallback                           |
| Folder metadata decryption | Custom decryptor   | `decryptFolderMetadata()` from `@cipherbox/crypto`              | Handles v2 format, validates structure                         |
| File metadata decryption   | Custom decryptor   | `decryptFileMetadata()` (implied by `file-metadata.service.ts`) | Same pattern as folder metadata                                |
| Modal UI                   | Custom modal       | `Modal` component from `components/ui/Modal.tsx`                | Already styled for CipherBox terminal aesthetic                |
| Context menu positioning   | Custom positioning | `@floating-ui/react` (already used in `ContextMenu.tsx`)        | Edge detection, viewport flipping                              |
| Hex encoding               | Custom encoder     | `bytesToHex()` / `hexToBytes()` from `@cipherbox/crypto`        | Already used throughout codebase                               |

---

## 10. Common Pitfalls

### Pitfall 1: Forgetting to Re-Wrap New File Keys for Existing Recipients

**What goes wrong:** Sharer adds a file to a shared folder but doesn't re-wrap the new file's key for existing recipients. Recipient can see the new file name in metadata but cannot download it.

**Why it happens:** The normal upload flow only wraps keys with the owner's publicKey. The sharing extension must intercept this flow.

**How to avoid:** After any file upload/modification in a folder with active shares, check for share records and batch re-wrap new keys. Implement this as a post-upload hook in the upload service.

**Warning signs:** Recipient sees a file in shared folder but gets "Key unwrapping failed" on download.

### Pitfall 2: Race Between Share Creation and Folder Modification

**What goes wrong:** Sharer starts sharing a folder (re-wrapping all keys) while simultaneously adding files. The new files' keys don't get included in the share batch.

**Why it happens:** The re-wrapping traversal and the file upload happen concurrently.

**How to avoid:** Use optimistic locking or serialize share creation with folder modifications. The simplest approach: show a "sharing in progress" state that prevents modifications until all keys are re-wrapped.

### Pitfall 3: Stale Recipient Key Cache

**What goes wrong:** After key rotation (on revoke), remaining recipients still have the old folderKey cached in their share store. They try to decrypt new metadata with the old key and get decryption failure.

**Why it happens:** The recipient's cache isn't invalidated when the sharer rotates keys.

**How to avoid:** On decryption failure for a shared folder, re-fetch the share record from the API to get the updated encrypted key. Implement a retry-with-refresh pattern.

### Pitfall 4: Sharing Root Folder Leaks Everything

**What goes wrong:** User shares their root folder, effectively giving the recipient access to their entire vault.

**Why it happens:** No guard preventing root folder sharing.

**How to avoid:** Either (a) disallow sharing the root folder, or (b) show a clear warning. Recommendation: disallow sharing root folder in Phase 14.

### Pitfall 5: Re-Wrapping Performance for Large Folder Trees

**What goes wrong:** Sharing a folder with thousands of files takes minutes due to sequential ECIES operations.

**Why it happens:** Each re-wrapping is an independent ECIES encryption.

**How to avoid:** Batch ECIES operations in parallel (Promise.all). The `wrapKey()` function is async and CPU-bound (secp256k1 point multiplication), so parallelism helps on multi-core systems. Also show progress UI during share creation.

### Pitfall 6: Recipient Cannot Resolve Newly-Published IPNS

**What goes wrong:** Sharer shares a folder, publishes IPNS update, recipient immediately tries to resolve and gets stale CID.

**Why it happens:** IPNS propagation takes time (same issue as subfolder navigation, handled by retry in `useFolderNavigation`).

**How to avoid:** Use the same retry pattern as `useFolderNavigation` (3 retries, 2s delay). Also consider using the DB-cached CID fallback from `ipns.service.ts`.

---

## 11. Code Examples

### Re-Wrapping a Key for a Recipient

```typescript
// Source: packages/crypto/src/ecies/encrypt.ts + decrypt.ts
import { wrapKey, unwrapKey } from '@cipherbox/crypto';

/**
 * Re-wrap a key from owner encryption to recipient encryption.
 * This is the core sharing operation.
 */
async function reWrapKey(
  ownerWrappedKey: Uint8Array, // ECIES ciphertext wrapped with owner's pubkey
  ownerPrivateKey: Uint8Array, // Owner's secp256k1 private key (32 bytes)
  recipientPublicKey: Uint8Array // Recipient's secp256k1 public key (65 bytes)
): Promise<Uint8Array> {
  // 1. Unwrap: decrypt with owner's private key
  const plainKey = await unwrapKey(ownerWrappedKey, ownerPrivateKey);

  // 2. Re-wrap: encrypt with recipient's public key
  const recipientWrapped = await wrapKey(plainKey, recipientPublicKey);

  // 3. Zero the plaintext key from memory
  plainKey.fill(0);

  return recipientWrapped;
}
```

### Validating a Recipient Public Key

```typescript
// Source: packages/crypto/src/ecies/encrypt.ts (validation logic)
import { ProjectivePoint } from '@noble/secp256k1';
import { SECP256K1_PUBLIC_KEY_SIZE } from '@cipherbox/crypto';

function validateRecipientPublicKey(hexKey: string): Uint8Array {
  // Remove 0x prefix if present
  const cleanHex = hexKey.startsWith('0x') ? hexKey.slice(2) : hexKey;

  // Convert to bytes
  const bytes = hexToBytes(cleanHex);

  // Check size (65 bytes uncompressed)
  if (bytes.length !== SECP256K1_PUBLIC_KEY_SIZE) {
    throw new Error('Invalid public key size. Expected 65-byte uncompressed key.');
  }

  // Check 0x04 prefix
  if (bytes[0] !== 0x04) {
    throw new Error('Invalid public key format. Expected uncompressed key (0x04 prefix).');
  }

  // Validate curve point
  try {
    ProjectivePoint.fromHex(bytes);
  } catch {
    throw new Error('Invalid public key. Not a valid point on secp256k1 curve.');
  }

  return bytes;
}
```

### Share Dialog Data Flow

```typescript
// Sharing a folder: client-side flow
async function shareFolder(
  folderId: string,
  folderKey: Uint8Array,
  recipientPublicKeyHex: string,
  ownerPrivateKey: Uint8Array,
  folderNode: FolderNode
): Promise<void> {
  // 1. Validate recipient
  const recipientPubKey = validateRecipientPublicKey(recipientPublicKeyHex);

  // 2. Check recipient exists
  const user = await api.get(`/users/lookup?publicKey=${recipientPublicKeyHex}`);
  if (!user) throw new Error('Recipient not found');

  // 3. Re-wrap folder key for recipient
  const wrappedFolderKey = await wrapKey(folderKey, recipientPubKey);

  // 4. Re-wrap all child keys
  const childKeys: Array<{ keyType: string; itemId: string; encryptedKey: Uint8Array }> = [];

  for (const child of folderNode.children) {
    if (child.type === 'file') {
      // Resolve file metadata to get fileKeyEncrypted
      const fileMeta = await resolveAndDecryptFileMetadata(child.fileMetaIpnsName, folderKey);
      const fileKey = await unwrapKey(hexToBytes(fileMeta.fileKeyEncrypted), ownerPrivateKey);
      const wrappedFileKey = await wrapKey(fileKey, recipientPubKey);
      fileKey.fill(0);

      childKeys.push({ keyType: 'file', itemId: child.id, encryptedKey: wrappedFileKey });
    } else if (child.type === 'folder') {
      const subfolderKey = await unwrapKey(hexToBytes(child.folderKeyEncrypted), ownerPrivateKey);
      const wrappedSubfolderKey = await wrapKey(subfolderKey, recipientPubKey);
      subfolderKey.fill(0);

      childKeys.push({ keyType: 'folder', itemId: child.id, encryptedKey: wrappedSubfolderKey });

      // TODO: Recursively handle subfolder children
    }
  }

  // 5. Send share record to API
  await api.post('/shares', {
    recipientPublicKey: recipientPublicKeyHex,
    itemType: 'folder',
    ipnsName: folderNode.ipnsName,
    itemName: folderNode.name,
    encryptedKey: bytesToHex(wrappedFolderKey),
    childKeys: childKeys.map((k) => ({
      keyType: k.keyType,
      itemId: k.itemId,
      encryptedKey: bytesToHex(k.encryptedKey),
    })),
  });
}
```

---

## 12. State of the Art

| Old Approach                     | Current Approach                   | When Changed                 | Impact                                            |
| -------------------------------- | ---------------------------------- | ---------------------------- | ------------------------------------------------- |
| Proxy re-encryption (PRE)        | Direct ECIES re-wrapping           | Design decision (CONTEXT.md) | Simpler, uses existing `wrapKey()`, no new crypto |
| Accept/decline flow              | Instant share (no invitation)      | CONTEXT.md decision          | Simpler UX, fewer API states                      |
| Immediate key rotation on revoke | Lazy rotation on next modification | CONTEXT.md decision          | Fewer forced re-encryption storms                 |
| Email/username lookup            | Direct public key paste            | CONTEXT.md decision          | No PII in system, out-of-band key exchange        |

---

## 13. Risk Assessment

### High Risk: Re-Wrapping Performance for Large Folders

**Likelihood:** MEDIUM (most folders have <100 files)
**Impact:** HIGH (poor UX for large folders, potential timeout)
**Mitigation:** Parallel ECIES operations, progress UI, depth limit on initial share (re-wrap only immediate children, lazy-load deeper)

### Medium Risk: Consistency Between Share Records and Metadata

**Likelihood:** MEDIUM (race conditions between file operations and sharing)
**Impact:** MEDIUM (recipient sees file but can't download)
**Mitigation:** Post-upload hook checks for active shares, retry pattern on client

### Low Risk: Key Rotation Correctness

**Likelihood:** LOW (well-defined protocol)
**Impact:** HIGH if wrong (security breach)
**Mitigation:** Extensive test vectors for rotation flow, integration tests

---

## 14. Recommended Plan Structure

Based on this research, the implementation should be structured as:

### Backend Work

1. **Database migration** -- Create `shares` and `share_keys` tables
2. **Share module** -- NestJS module with controller, service, DTOs
3. **User lookup endpoint** -- Verify publicKey belongs to registered user
4. **API client regeneration** -- `pnpm api:generate`

### Crypto Package Work

5. **Re-wrap utility** -- `reWrapKey()` function in `packages/crypto/src/ecies/`
6. **Share key types** -- Type definitions for share records
7. **Test vectors** -- Verify re-wrapping correctness with multiple key pairs

### Web App Work

8. **Share store** -- Zustand store for received/sent shares
9. **Share dialog** -- Modal for creating shares (paste pubkey, show recipients)
10. **Context menu integration** -- Add "Share" item to context menu
11. **Details dialog integration** -- Add shares tab to details dialog
12. **"Shared with me" section** -- New route, breadcrumb navigation
13. **Shared folder browsing** -- Read-only folder/file browsing using share keys
14. **Shared file download** -- Download shared files using re-wrapped file keys
15. **Revocation flow** -- Remove recipients, trigger lazy rotation flag
16. **Settings: public key display** -- Show user's public key with copy button
17. **Read-only enforcement** -- Disable write actions in shared context

### Cross-Cutting

18. **Post-upload hook** -- When uploading to a shared folder, re-wrap keys for recipients
19. **Lazy key rotation** -- Implement rotation on next modification after revoke

---

## Open Questions

1. **Recursive subfolder sharing depth:** When sharing a folder with subfolders, should we recursively re-wrap ALL descendant keys at share time, or lazy-load subfolder keys when the recipient navigates into them? Recursive is simpler but expensive. Lazy requires the sharer to be online when the recipient navigates.

   **Recommendation:** Recursive re-wrap at share time. The sharer is already online (they're creating the share), and the ECIES operations are fast enough for reasonable folder trees. Cap at a configurable depth or item count with a warning.

2. **Display name for shared items:** The share record needs a display name visible to the recipient before they decrypt anything. Should this name be plaintext (visible to server) or encrypted (requires extra wrapping)?

   **Recommendation:** Plaintext. The server already knows who shared with whom; the folder/file name adds minimal privacy exposure. If strict zero-knowledge is required, encrypt the name with recipient's publicKey.

3. **Share polling frequency:** How often should recipients poll for new shares? Every 30s (same as sync) or less frequently?

   **Recommendation:** Every 60 seconds, or combined with the existing 30s sync poll as an additional API call. Shares are infrequent events.

---

## Sources

### Primary (HIGH confidence)

- `packages/crypto/src/ecies/encrypt.ts` -- wrapKey implementation
- `packages/crypto/src/ecies/decrypt.ts` -- unwrapKey implementation
- `packages/crypto/src/__tests__/ecies.test.ts` -- ECIES round-trip tests
- `packages/crypto/src/folder/types.ts` -- FolderMetadata, FolderEntry, FolderChild types
- `packages/crypto/src/file/types.ts` -- FileMetadata, FilePointer, VersionEntry types
- `apps/api/src/ipns/entities/folder-ipns.entity.ts` -- IPNS record entity pattern
- `apps/api/src/auth/entities/user.entity.ts` -- User entity (publicKey field)
- `apps/web/src/stores/folder.store.ts` -- Folder tree state management
- `apps/web/src/hooks/useFolderNavigation.ts` -- Folder browsing architecture
- `apps/web/src/services/folder.service.ts` -- Folder CRUD with encryption
- `docs/METADATA_SCHEMAS.md` -- All metadata schema definitions
- `docs/METADATA_EVOLUTION_PROTOCOL.md` -- Schema change rules
- `00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md` -- Key hierarchy, ECIES specs
- `00-Preliminary-R&D/Documentation/API_SPECIFICATION.md` -- Existing API patterns, DB schema

### Secondary (MEDIUM confidence)

- `eciesjs` v0.4.16 npm package -- ECIES implementation used by CipherBox

---

## Metadata

**Confidence breakdown:**

- ECIES Re-wrapping: HIGH -- uses existing verified crypto functions, no new primitives
- Share Record Storage: HIGH -- follows existing NestJS entity patterns
- Recipient Browsing: HIGH -- extends existing folder navigation architecture
- Lazy Key Rotation: MEDIUM -- well-defined protocol but untested, needs careful implementation
- File-Level Sharing: HIGH -- clean architectural fit with per-file IPNS
- Version History: MEDIUM -- open question, recommendation is to defer

**Research date:** 2026-02-21
**Valid until:** 2026-03-21 (stable domain, no external dependencies changing)
