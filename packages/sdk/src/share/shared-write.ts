/**
 * @cipherbox/sdk - Shared-write operations
 *
 * Stateless functions for write operations on shared folders.
 * Extracted from: apps/web/src/hooks/useSharedNavigation.ts (write handlers)
 *
 * Each function takes explicit context (keys, IPNS state, callbacks) and
 * returns updated state. No React/Zustand/browser dependencies.
 *
 * Key wrapping convention for shared folders:
 * - FolderEntry/FilePointer fields wrap keys with the OWNER's public key
 *   (so the owner can access their own data)
 * - share_keys entries wrap keys with the RECIPIENT's public key
 *   (so the share recipient can access)
 */

import {
  encryptAesGcm,
  generateFileKey,
  generateIv,
  wrapKey,
  bytesToHex,
  generateRandomBytes,
  generateEd25519Keypair,
  deriveIpnsName,
} from '@cipherbox/crypto';
import {
  generateFileIpnsKeypair,
  encryptFolderMetadata,
  encryptFileMetadata,
  createIpnsRecord,
  marshalIpnsRecord,
  type FolderChild,
  type FolderEntry,
  type FilePointer,
  type FileMetadata,
  type FolderMetadata,
} from '@cipherbox/core';
import {
  updateFolderMetadataAndPublish,
  addToIpfs,
  batchPublishIpnsRecords,
  createAndPublishIpnsRecord,
  resolveFileMetadata,
  updateFileMetadata,
  unpinFromIpfs,
  moveItem,
} from '@cipherbox/sdk-core';
import type { SdkContext } from '@cipherbox/sdk-core';
import { reencryptFileMetadataForFolderChange } from '../reencrypt';
import type { ShareKeyEntryDtoKeyType } from '@cipherbox/api-client';

/** Re-export the canonical share key type for consumers */
export type ShareKeyType = ShareKeyEntryDtoKeyType;

/**
 * Context for shared-write operations on a folder.
 * Provides all state needed to modify folder contents and publish changes.
 */
export type SharedWriteContext = {
  /** SDK context for IPFS/IPNS API access */
  ctx: SdkContext;
  /** Decrypted AES-256 folder key for the current folder */
  folderKey: Uint8Array;
  /** Ed25519 private key for signing IPNS publishes */
  ipnsPrivateKey: Uint8Array;
  /** IPNS name of the current folder */
  ipnsName: string;
  /** Current sequence number for conflict detection */
  sequenceNumber: bigint;
  /** Current folder children */
  children: FolderChild[];
  /** Sharer's secp256k1 public key (keys in FolderEntry/FilePointer wrap for owner) */
  ownerPublicKey: Uint8Array;
  /** Current user's secp256k1 public key (keys in share_keys wrap for recipient) */
  recipientPublicKey: Uint8Array;
  /** Share ID for addShareKeysFn calls */
  shareId: string;
  /** Callback to add share keys for the recipient */
  addShareKeysFn: (
    shareId: string,
    keys: Array<{
      keyType: ShareKeyType;
      itemId: string;
      encryptedKey: string;
    }>
  ) => Promise<void>;
};

// ---------------------------------------------------------------------------
// Function 1: uploadToSharedFolder
// ---------------------------------------------------------------------------

/**
 * Upload a file to a write-shared folder.
 *
 * Encrypts the file content, creates per-file IPNS metadata, adds the
 * FilePointer to folder children, publishes the updated folder, and
 * registers share_keys for the recipient.
 *
 * Key wrapping:
 * - fileKey wrapped with ownerPublicKey -> FilePointer.fileKeyEncrypted (owner access)
 * - fileKey wrapped with recipientPublicKey -> share_keys file key (recipient access)
 * - IPNS private key wrapped with ownerPublicKey -> FilePointer.ipnsPrivateKeyEncrypted
 * - IPNS private key wrapped with recipientPublicKey -> share_keys file-ipns key
 */
export async function uploadToSharedFolder(
  swCtx: SharedWriteContext,
  params: { data: Uint8Array; fileName: string; mimeType?: string }
): Promise<{
  publishedChildren: FolderChild[];
  newSequenceNumber: bigint;
  filePointer: FilePointer;
}> {
  const fileKey = generateFileKey();
  const iv = generateIv();

  try {
    // 1. Encrypt file content
    const ciphertext = await encryptAesGcm(params.data, fileKey, iv);

    // 2. Upload encrypted content to IPFS
    const { cid: contentCid } = await addToIpfs(swCtx.ctx, new Uint8Array(ciphertext));

    // 3. Wrap fileKey with owner's public key (for FilePointer)
    const ownerWrappedFileKey = await wrapKey(fileKey, swCtx.ownerPublicKey);
    const fileKeyEncrypted = bytesToHex(ownerWrappedFileKey);

    // 4. Generate IPNS keypair for file metadata
    const fileId = crypto.randomUUID();
    const mimeType = params.mimeType ?? 'application/octet-stream';
    const ipnsKeypair = await generateFileIpnsKeypair();

    try {
      // 5. Wrap IPNS private key for owner (FilePointer) and recipient (share_keys)
      const ownerWrappedIpnsKey = await wrapKey(ipnsKeypair.privateKey, swCtx.ownerPublicKey);
      const ipnsPrivateKeyEncrypted = bytesToHex(ownerWrappedIpnsKey);
      const recipientWrappedIpnsKey = await wrapKey(
        ipnsKeypair.privateKey,
        swCtx.recipientPublicKey
      );

      // 6. Create and encrypt file metadata
      const now = Date.now();
      const fileMeta: FileMetadata = {
        version: 'v1',
        cid: contentCid,
        fileKeyEncrypted,
        fileIv: bytesToHex(iv),
        size: params.data.length,
        mimeType,
        encryptionMode: 'GCM',
        createdAt: now,
        modifiedAt: now,
      };
      const encrypted = await encryptFileMetadata(fileMeta, swCtx.folderKey);

      // 7. Upload encrypted metadata to IPFS
      const jsonStr = JSON.stringify(encrypted);
      const metadataBytes = new TextEncoder().encode(jsonStr);
      const { cid: metadataCid } = await addToIpfs(swCtx.ctx, metadataBytes);

      // 8. Create and publish file IPNS record
      // Use createAndPublishIpnsRecord for single file IPNS, then batch publish
      const ipnsLifetimeMs = 24 * 60 * 60 * 1000;
      const record = await createIpnsRecord(
        ipnsKeypair.privateKey,
        `/ipfs/${metadataCid}`,
        1n,
        ipnsLifetimeMs
      );
      const recordBytes = marshalIpnsRecord(record);
      let binary = '';
      for (let i = 0; i < recordBytes.length; i++) {
        binary += String.fromCharCode(recordBytes[i]);
      }
      const recordBase64 = btoa(binary);

      await batchPublishIpnsRecords(
        [
          {
            ipnsName: ipnsKeypair.ipnsName,
            recordBase64,
            metadataCid,
            recordType: 'file' as const,
          },
        ],
        swCtx.ctx
      );

      // 9. Build FilePointer (owner-wrapped keys)
      const filePointer: FilePointer = {
        type: 'file',
        id: fileId,
        name: params.fileName,
        fileMetaIpnsName: ipnsKeypair.ipnsName,
        ipnsPrivateKeyEncrypted,
        createdAt: now,
        modifiedAt: now,
      };

      // 10. Add file to folder children and publish
      const updatedChildren = [...swCtx.children, filePointer];
      const { newSequenceNumber, publishedChildren } = await updateFolderMetadataAndPublish({
        children: updatedChildren,
        baseChildren: swCtx.children,
        folderKey: swCtx.folderKey,
        ipnsPrivateKey: swCtx.ipnsPrivateKey,
        ipnsName: swCtx.ipnsName,
        sequenceNumber: swCtx.sequenceNumber,
        ctx: swCtx.ctx,
      });

      // 11. Add share_keys for recipient (file + file-ipns)
      const recipientWrappedFileKey = await wrapKey(fileKey, swCtx.recipientPublicKey);
      try {
        await swCtx.addShareKeysFn(swCtx.shareId, [
          { keyType: 'file', itemId: fileId, encryptedKey: bytesToHex(recipientWrappedFileKey) },
          {
            keyType: 'file-ipns',
            itemId: fileId,
            encryptedKey: bytesToHex(recipientWrappedIpnsKey),
          },
        ]);
      } catch (err) {
        console.warn('[shared-write] Failed to add share_keys for uploaded file:', err);
      }

      return { publishedChildren, newSequenceNumber, filePointer };
    } finally {
      ipnsKeypair.privateKey.fill(0);
    }
  } finally {
    fileKey.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Function 2: createSharedSubfolder
// ---------------------------------------------------------------------------

/**
 * Create a subfolder in a write-shared folder.
 *
 * Generates an Ed25519 keypair and AES-256 folder key, wraps with owner's
 * key for FolderEntry, publishes empty subfolder IPNS, adds FolderEntry to
 * parent, publishes parent, and registers share_keys for the recipient.
 */
export async function createSharedSubfolder(
  swCtx: SharedWriteContext,
  params: { name: string }
): Promise<{
  publishedChildren: FolderChild[];
  newSequenceNumber: bigint;
  folderEntry: FolderEntry;
}> {
  // Generate Ed25519 keypair for the subfolder IPNS
  const keypair = await generateEd25519Keypair();
  const subfolderIpnsName = await deriveIpnsName(keypair.publicKey);

  // Generate AES-256 folder key for the subfolder
  const subfolderKey = generateRandomBytes(32);

  try {
    // 1. Wrap keys with owner's public key (for FolderEntry)
    const wrappedFolderKey = await wrapKey(subfolderKey, swCtx.ownerPublicKey);
    const wrappedIpnsKey = await wrapKey(keypair.privateKey, swCtx.ownerPublicKey);

    // 2. Create and encrypt empty folder metadata
    const subfolderMetadata: FolderMetadata = { version: 'v2', children: [] };
    const encrypted = await encryptFolderMetadata(subfolderMetadata, subfolderKey);
    const jsonStr = JSON.stringify(encrypted);
    const encryptedBytes = new TextEncoder().encode(jsonStr);
    const { cid: subfolderCid } = await addToIpfs(swCtx.ctx, encryptedBytes);

    // 3. Publish subfolder IPNS
    await createAndPublishIpnsRecord({
      ipnsPrivateKey: keypair.privateKey,
      ipnsName: subfolderIpnsName,
      metadataCid: subfolderCid,
      sequenceNumber: 1n,
      ctx: swCtx.ctx,
    });

    // 4. Create FolderEntry for the parent
    const folderId = crypto.randomUUID();
    const folderEntry: FolderEntry = {
      type: 'folder',
      id: folderId,
      name: params.name,
      ipnsName: subfolderIpnsName,
      ipnsPrivateKeyEncrypted: bytesToHex(wrappedIpnsKey),
      folderKeyEncrypted: bytesToHex(wrappedFolderKey),
      createdAt: Date.now(),
      modifiedAt: Date.now(),
    };

    // 5. Add to parent folder and publish
    const updatedChildren = [...swCtx.children, folderEntry];
    const { newSequenceNumber, publishedChildren } = await updateFolderMetadataAndPublish({
      children: updatedChildren,
      baseChildren: swCtx.children,
      folderKey: swCtx.folderKey,
      ipnsPrivateKey: swCtx.ipnsPrivateKey,
      ipnsName: swCtx.ipnsName,
      sequenceNumber: swCtx.sequenceNumber,
      ctx: swCtx.ctx,
    });

    // 6. Add share_keys for recipient (folder + folder-ipns)
    const recipientWrappedFolderKey = await wrapKey(subfolderKey, swCtx.recipientPublicKey);
    const recipientWrappedIpnsKey = await wrapKey(keypair.privateKey, swCtx.recipientPublicKey);
    try {
      await swCtx.addShareKeysFn(swCtx.shareId, [
        {
          keyType: 'folder',
          itemId: folderId,
          encryptedKey: bytesToHex(recipientWrappedFolderKey),
        },
        {
          keyType: 'folder-ipns',
          itemId: folderId,
          encryptedKey: bytesToHex(recipientWrappedIpnsKey),
        },
      ]);
    } catch (err) {
      console.warn('[shared-write] Failed to add share_keys for subfolder:', err);
    }

    return { publishedChildren, newSequenceNumber, folderEntry };
  } finally {
    subfolderKey.fill(0);
    keypair.privateKey.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Function 3: renameInSharedFolder
// ---------------------------------------------------------------------------

/**
 * Rename an item in a write-shared folder.
 *
 * Maps over children to update the name and modifiedAt, then publishes
 * the updated folder metadata.
 */
export async function renameInSharedFolder(
  swCtx: SharedWriteContext,
  params: { itemId: string; newName: string }
): Promise<{
  publishedChildren: FolderChild[];
  newSequenceNumber: bigint;
}> {
  const updatedChildren = swCtx.children.map((child) =>
    child.id === params.itemId ? { ...child, name: params.newName, modifiedAt: Date.now() } : child
  );

  const { newSequenceNumber, publishedChildren } = await updateFolderMetadataAndPublish({
    children: updatedChildren,
    baseChildren: swCtx.children,
    folderKey: swCtx.folderKey,
    ipnsPrivateKey: swCtx.ipnsPrivateKey,
    ipnsName: swCtx.ipnsName,
    sequenceNumber: swCtx.sequenceNumber,
    ctx: swCtx.ctx,
  });

  return { publishedChildren, newSequenceNumber };
}

// ---------------------------------------------------------------------------
// Function 4: deleteFromSharedFolder
// ---------------------------------------------------------------------------

/**
 * Delete an item from a write-shared folder.
 *
 * Filters the item from children and publishes the updated folder metadata.
 */
export async function deleteFromSharedFolder(
  swCtx: SharedWriteContext,
  params: { itemId: string }
): Promise<{
  publishedChildren: FolderChild[];
  newSequenceNumber: bigint;
}> {
  const updatedChildren = swCtx.children.filter((child) => child.id !== params.itemId);

  const { newSequenceNumber, publishedChildren } = await updateFolderMetadataAndPublish({
    children: updatedChildren,
    baseChildren: swCtx.children,
    folderKey: swCtx.folderKey,
    ipnsPrivateKey: swCtx.ipnsPrivateKey,
    ipnsName: swCtx.ipnsName,
    sequenceNumber: swCtx.sequenceNumber,
    ctx: swCtx.ctx,
  });

  return { publishedChildren, newSequenceNumber };
}

// ---------------------------------------------------------------------------
// Function 5: updateSharedFile
// ---------------------------------------------------------------------------

/**
 * Update a file's content in a write-shared context.
 *
 * Encrypts new content, uploads to IPFS, resolves current file metadata,
 * updates the file metadata IPNS record, and refreshes the recipient's
 * share_key for the file.
 *
 * Does NOT modify folder metadata (the FilePointer stays the same).
 */
export async function updateSharedFile(params: {
  ctx: SdkContext;
  folderKey: Uint8Array;
  ownerPublicKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  shareId: string;
  addShareKeysFn: (
    shareId: string,
    keys: Array<{
      keyType: ShareKeyType;
      itemId: string;
      encryptedKey: string;
    }>
  ) => Promise<void>;
  filePointer: FilePointer;
  newContent: Uint8Array;
  /** Callback to get the file's IPNS private key (checks share_keys then FilePointer fallback) */
  getFileIpnsKeyFn: (itemId: string) => Promise<Uint8Array | null>;
}): Promise<void> {
  // 1. Encrypt new content
  const fileKey = generateFileKey();
  const iv = generateIv();

  try {
    const ciphertext = await encryptAesGcm(params.newContent, fileKey, iv);

    // 2. Upload encrypted content to IPFS
    const { cid: contentCid } = await addToIpfs(params.ctx, new Uint8Array(ciphertext));

    // 3. Wrap fileKey with owner's public key
    const ownerWrappedKey = await wrapKey(fileKey, params.ownerPublicKey);
    const fileKeyEncrypted = bytesToHex(ownerWrappedKey);

    // 4. Get the file's IPNS private key
    const ipnsPrivKey = await params.getFileIpnsKeyFn(params.filePointer.id);
    if (!ipnsPrivKey) {
      throw new Error('Cannot update: no file IPNS key available');
    }

    try {
      // 5. Resolve current file metadata
      const { metadata: currentMeta } = await resolveFileMetadata(
        params.filePointer.fileMetaIpnsName,
        params.folderKey,
        params.ctx
      );

      // 6. Update file metadata (publishes internally via CAS — Plan 03)
      const { prunedCids } = await updateFileMetadata({
        fileIpnsPrivateKey: ipnsPrivKey,
        fileMetaIpnsName: params.filePointer.fileMetaIpnsName,
        folderKey: params.folderKey,
        currentMetadata: currentMeta,
        updates: {
          cid: contentCid,
          fileKeyEncrypted,
          fileIv: bytesToHex(iv),
          size: params.newContent.length,
          encryptionMode: 'GCM',
        },
        createVersion: false,
        ctx: params.ctx,
      });

      // 7. Unpin version-history CIDs pruned by the per-file version cap, mirroring
      // the owner path (useFileOperations.ts). Fire-and-forget: the Phase-42
      // server-side guarded-unpin (ownership + cross-user refcount) blocks any actual
      // cross-user unpin and returns 403 for a CID the recipient does not own; that
      // rejection is caught and logged, never propagated, so a share write never fails
      // on an unpin (T-47-04).
      for (const cid of prunedCids) {
        unpinFromIpfs(params.ctx, cid).catch((err) => {
          console.warn('[shared-write] Unpin pruned CID failed:', err);
        });
      }

      // 8. Update share_key for recipient
      const recipientWrappedKey = await wrapKey(fileKey, params.recipientPublicKey);
      try {
        await params.addShareKeysFn(params.shareId, [
          {
            keyType: 'file',
            itemId: params.filePointer.id,
            encryptedKey: bytesToHex(recipientWrappedKey),
          },
        ]);
      } catch (err) {
        console.warn('[shared-write] Failed to update share_key after file edit:', err);
      }
    } finally {
      ipnsPrivKey.fill(0);
    }
  } finally {
    fileKey.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Function 6: moveInSharedFolder (stateless op)
// ---------------------------------------------------------------------------

/**
 * Move an item between two subfolders within a single shared folder.
 *
 * Mirrors the owner `moveItem` publish ordering (DEST first → re-key → SOURCE).
 * Does NOT zero any key material — the caller owns all zeroing in a `finally` block.
 *
 * @param params.ctx - SDK context for IPFS/IPNS API access
 * @param params.srcCtx - Source folder context (keys, children, sequence)
 * @param params.destCtx - Destination folder context (keys, children, sequence — loaded fresh)
 * @param params.itemId - ID of the item to move (from srcCtx.children)
 * @param params.fileIpnsPrivateKey - Pre-resolved file IPNS private key from share_keys
 *   keyType:'file-ipns'; null for folder items. Caller owns zeroing in finally.
 */
export async function moveInSharedFolder(params: {
  ctx: SdkContext;
  srcCtx: {
    folderKey: Uint8Array;
    ipnsPrivateKey: Uint8Array;
    ipnsName: string;
    sequenceNumber: bigint;
    children: FolderChild[];
  };
  destCtx: {
    folderKey: Uint8Array;
    ipnsPrivateKey: Uint8Array;
    ipnsName: string;
    sequenceNumber: bigint;
    children: FolderChild[];
  };
  itemId: string;
  fileIpnsPrivateKey: Uint8Array | null;
}): Promise<{
  srcResult: { publishedChildren: FolderChild[]; newSequenceNumber: bigint };
  destResult: { publishedChildren: FolderChild[]; newSequenceNumber: bigint };
}> {
  // 1. Pure source/dest children mutation — throws on name collision or item-not-found
  const { updatedSourceChildren, updatedDestChildren, movedItem } = moveItem({
    sourceChildren: params.srcCtx.children,
    destChildren: params.destCtx.children,
    childId: params.itemId,
  });

  // 2. Publish DEST first (add-before-remove crash safety)
  const destResult = await updateFolderMetadataAndPublish({
    children: updatedDestChildren,
    baseChildren: params.destCtx.children,
    folderKey: params.destCtx.folderKey,
    ipnsPrivateKey: params.destCtx.ipnsPrivateKey,
    ipnsName: params.destCtx.ipnsName,
    sequenceNumber: params.destCtx.sequenceNumber,
    ctx: params.ctx,
  });

  // 3. If file: re-seal FileMetadata under dest folderKey (done AFTER dest publish)
  if (movedItem.type === 'file' && params.fileIpnsPrivateKey) {
    const fp = movedItem as FilePointer;
    await reencryptFileMetadataForFolderChange({
      fileMetaIpnsName: fp.fileMetaIpnsName,
      fileIpnsPrivateKey: params.fileIpnsPrivateKey,
      sourceFolderKey: params.srcCtx.folderKey,
      destFolderKey: params.destCtx.folderKey,
      ctx: params.ctx,
    });
    // Caller owns zeroing fileIpnsPrivateKey in finally — NOT this function.
  }

  // 4. Publish SOURCE (remove)
  const srcResult = await updateFolderMetadataAndPublish({
    children: updatedSourceChildren,
    baseChildren: params.srcCtx.children,
    folderKey: params.srcCtx.folderKey,
    ipnsPrivateKey: params.srcCtx.ipnsPrivateKey,
    ipnsName: params.srcCtx.ipnsName,
    sequenceNumber: params.srcCtx.sequenceNumber,
    ctx: params.ctx,
  });

  return { srcResult, destResult };
}

// ---------------------------------------------------------------------------
// Function 7: updateSharePermission
// ---------------------------------------------------------------------------

/**
 * Update a share's permission level.
 *
 * Thin callback wrapper consistent with the existing revokeShare pattern.
 */
export async function updateSharePermission(params: {
  shareId: string;
  permission: string;
  encryptedIpnsKey?: string;
  updatePermissionFn: (
    shareId: string,
    body: { permission: string; encryptedIpnsKey?: string }
  ) => Promise<void>;
}): Promise<void> {
  await params.updatePermissionFn(params.shareId, {
    permission: params.permission,
    encryptedIpnsKey: params.encryptedIpnsKey,
  });
}
