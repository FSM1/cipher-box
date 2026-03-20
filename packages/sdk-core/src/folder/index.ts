/**
 * Folder operations - Stateless folder CRUD with encryption
 *
 * Extracted from: apps/web/src/services/folder.service.ts
 * All store access replaced with explicit parameters.
 * Functions take metadata in, return updated metadata out.
 */

import {
  generateEd25519Keypair,
  deriveIpnsName,
  generateRandomBytes,
  wrapKey,
  bytesToHex,
  hexToBytes,
} from '@cipherbox/crypto';
import {
  encryptFolderMetadata,
  decryptFolderMetadata,
  type FolderMetadata,
  type EncryptedFolderMetadata,
  type FolderEntry,
  type FolderChild,
  type FilePointer,
} from '@cipherbox/core';
import type { SdkContext, TeeKeys } from '../types';
import { addToIpfs, fetchFromIpfs } from '../ipfs';
import { createAndPublishIpnsRecord, resolveIpnsRecord } from '../ipns';

/**
 * Fetch and decrypt folder metadata from IPFS.
 *
 * @param cid - IPFS CID of the encrypted metadata blob
 * @param folderKey - Decrypted AES-256 folder key
 * @param ctx - SDK context for IPFS access
 * @returns Decrypted folder metadata (v2)
 */
export async function fetchAndDecryptMetadata(
  cid: string,
  folderKey: Uint8Array,
  ctx: SdkContext
): Promise<FolderMetadata> {
  const encryptedBytes = await fetchFromIpfs(ctx, cid);
  const encryptedJson = new TextDecoder().decode(encryptedBytes);
  const encrypted: EncryptedFolderMetadata = JSON.parse(encryptedJson);
  return decryptFolderMetadata(encrypted, folderKey);
}

/**
 * Load a folder's metadata from IPNS.
 *
 * Resolves the folder's IPNS name to get the current metadata CID,
 * fetches and decrypts the metadata.
 *
 * @returns Decrypted folder metadata, sequence number, and CID, or null if IPNS not found
 */
export async function loadFolderMetadata(params: {
  ipnsName: string;
  folderKey: Uint8Array;
  ctx: SdkContext;
}): Promise<{
  metadata: FolderMetadata;
  sequenceNumber: bigint;
  cid: string;
} | null> {
  const resolved = await resolveIpnsRecord(params.ipnsName);
  if (!resolved) return null;

  const metadata = await fetchAndDecryptMetadata(resolved.cid, params.folderKey, params.ctx);

  return {
    metadata,
    sequenceNumber: resolved.sequenceNumber,
    cid: resolved.cid,
  };
}

/**
 * Create a new subfolder with generated keys.
 *
 * Generates new Ed25519 IPNS keypair and AES-256 folder key,
 * wraps them with the user's public key for storage.
 *
 * @returns Created folder entry and decrypted keys
 */
export async function createSubfolder(params: {
  name: string;
  userPublicKey: Uint8Array;
  teeKeys?: TeeKeys;
}): Promise<{
  folder: FolderEntry;
  ipnsPrivateKey: Uint8Array;
  folderKey: Uint8Array;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
}> {
  // 1. Generate Ed25519 keypair for folder IPNS
  const ipnsKeypair = await generateEd25519Keypair();
  const ipnsName = await deriveIpnsName(ipnsKeypair.publicKey);

  // 2. Generate random AES-256 folder key
  const folderKey = generateRandomBytes(32);

  // 3. Wrap keys with user's public key (ECIES encryption)
  const ipnsPrivateKeyEncrypted = bytesToHex(
    await wrapKey(ipnsKeypair.privateKey, params.userPublicKey)
  );
  const folderKeyEncrypted = bytesToHex(await wrapKey(folderKey, params.userPublicKey));

  // 4. TEE-02: Encrypt IPNS private key with TEE public key for republishing.
  //    Wrap remaining steps in try/catch to zero key material on error.
  //    On success the caller receives the keys, so we only zero on failure.
  try {
    let encryptedIpnsPrivateKey: string | undefined;
    let keyEpoch: number | undefined;

    if (params.teeKeys?.currentPublicKey) {
      const teePublicKey = hexToBytes(params.teeKeys.currentPublicKey);
      const encryptedKey = await wrapKey(ipnsKeypair.privateKey, teePublicKey);
      encryptedIpnsPrivateKey = bytesToHex(encryptedKey);
      keyEpoch = params.teeKeys.currentEpoch;
    }

    // 5. Create folder entry for parent's metadata
    const now = Date.now();
    const folder: FolderEntry = {
      type: 'folder',
      id: crypto.randomUUID(),
      name: params.name,
      ipnsName,
      ipnsPrivateKeyEncrypted,
      folderKeyEncrypted,
      createdAt: now,
      modifiedAt: now,
    };

    return {
      folder,
      ipnsPrivateKey: ipnsKeypair.privateKey,
      folderKey,
      encryptedIpnsPrivateKey,
      keyEpoch,
    };
  } catch (error) {
    ipnsKeypair.privateKey.fill(0);
    folderKey.fill(0);
    throw error;
  }
}

/**
 * Update folder metadata and publish to IPNS.
 *
 * Encrypts the metadata with the folder key, uploads to IPFS,
 * and publishes an updated IPNS record pointing to the new CID.
 *
 * @returns New CID and sequence number
 */
export async function updateFolderMetadataAndPublish(params: {
  children: FolderChild[];
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  ctx: SdkContext;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
}): Promise<{ cid: string; newSequenceNumber: bigint }> {
  // 1. Create v2 folder metadata
  const metadata: FolderMetadata = {
    version: 'v2',
    children: params.children,
  };

  // 2. Encrypt metadata with folder key
  const encrypted = await encryptFolderMetadata(metadata, params.folderKey);

  // 3. Upload to IPFS via backend relay
  const jsonStr = JSON.stringify(encrypted);
  const encryptedBytes = new TextEncoder().encode(jsonStr);
  const { cid } = await addToIpfs(params.ctx, encryptedBytes);

  // 4. Publish IPNS record with conflict retry
  //    On 409, resolve current seq from IPNS and retry once
  let currentSeq = params.sequenceNumber;

  for (let attempt = 0; attempt < 2; attempt++) {
    const newSeq = currentSeq + 1n;
    try {
      await createAndPublishIpnsRecord({
        ipnsPrivateKey: params.ipnsPrivateKey,
        ipnsName: params.ipnsName,
        metadataCid: cid,
        sequenceNumber: newSeq,
        encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
        keyEpoch: params.keyEpoch,
        expectedSequenceNumber: currentSeq.toString(),
      });
      return { cid, newSequenceNumber: newSeq };
    } catch (err) {
      const is409 =
        (err as Error & { status?: number }).status === 409 ||
        (err as Error & { response?: { status?: number } }).response?.status === 409;
      if (!is409 || attempt > 0) throw err;

      // Re-sync: resolve current seq from IPNS
      const resolved = await resolveIpnsRecord(params.ipnsName);
      if (resolved) {
        currentSeq = resolved.sequenceNumber;
      } else {
        throw err; // Can't resolve → give up
      }
    }
  }

  // Should not reach here, but TypeScript needs it
  throw new Error('Publish failed after retry');
}

/**
 * Rename a child entry (folder or file) in folder metadata.
 *
 * Pure metadata operation: returns updated children array without publishing.
 */
export function renameInFolder(params: {
  children: FolderChild[];
  childId: string;
  newName: string;
}): { updatedChildren: FolderChild[]; renamedChild: FolderChild } {
  const children = [...params.children];
  const index = children.findIndex((c) => c.id === params.childId);

  if (index === -1) throw new Error('Item not found');

  const nameExists = children.some((c) => c.name === params.newName && c.id !== params.childId);
  if (nameExists) throw new Error('An item with this name already exists');

  const renamedChild = {
    ...children[index],
    name: params.newName,
    modifiedAt: Date.now(),
  };
  children[index] = renamedChild;

  return { updatedChildren: children, renamedChild };
}

/**
 * Remove a child entry (folder or file) from folder metadata.
 *
 * Pure metadata operation: returns updated children array and the removed item.
 */
export function deleteFromFolder(params: { children: FolderChild[]; childId: string }): {
  updatedChildren: FolderChild[];
  removedItem: FolderChild;
} {
  const index = params.children.findIndex((c) => c.id === params.childId);
  if (index === -1) throw new Error('Item not found');

  const removedItem = params.children[index];
  const updatedChildren = params.children.filter((c) => c.id !== params.childId);

  return { updatedChildren, removedItem };
}

/**
 * Add a file pointer to folder children.
 *
 * Pure metadata operation: returns updated children array with the new file pointer.
 */
export function addFilePointerToFolder(params: {
  children: FolderChild[];
  fileId: string;
  fileName: string;
  fileMetaIpnsName: string;
  ipnsPrivateKeyEncrypted: string;
}): { updatedChildren: FolderChild[]; filePointer: FilePointer } {
  const nameExists = params.children.some((c) => c.name === params.fileName);
  if (nameExists) throw new Error('A file with this name already exists');

  const now = Date.now();
  const filePointer: FilePointer = {
    type: 'file',
    id: params.fileId,
    name: params.fileName,
    fileMetaIpnsName: params.fileMetaIpnsName,
    ipnsPrivateKeyEncrypted: params.ipnsPrivateKeyEncrypted,
    createdAt: now,
    modifiedAt: now,
  };

  return {
    updatedChildren: [...params.children, filePointer],
    filePointer,
  };
}

/**
 * Move a child entry between folders.
 *
 * Pure metadata operation: returns updated source and dest children arrays.
 * Uses add-before-remove pattern conceptually (caller publishes dest first, then source).
 */
export function moveItem(params: {
  sourceChildren: FolderChild[];
  destChildren: FolderChild[];
  childId: string;
}): {
  updatedSourceChildren: FolderChild[];
  updatedDestChildren: FolderChild[];
  movedItem: FolderChild;
} {
  const index = params.sourceChildren.findIndex((c) => c.id === params.childId);
  if (index === -1) throw new Error('Item not found');

  const movedItem = {
    ...params.sourceChildren[index],
    modifiedAt: Date.now(),
  };

  // Check name collision in destination
  const nameExists = params.destChildren.some((c) => c.name === movedItem.name);
  if (nameExists) {
    throw new Error('An item with this name already exists in destination');
  }

  const updatedSourceChildren = params.sourceChildren.filter((c) => c.id !== params.childId);
  const updatedDestChildren = [...params.destChildren, movedItem];

  return { updatedSourceChildren, updatedDestChildren, movedItem };
}
