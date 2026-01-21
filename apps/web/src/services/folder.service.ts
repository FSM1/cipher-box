/**
 * Folder Service - Folder CRUD operations with encryption
 *
 * Handles folder creation, loading, and metadata updates with
 * client-side encryption using @cipherbox/crypto.
 */

import {
  generateEd25519Keypair,
  deriveIpnsName,
  generateRandomBytes,
  wrapKey,
  bytesToHex,
  encryptFolderMetadata,
  type FolderMetadata,
  type FolderEntry,
  type FileEntry,
  type FolderChild,
} from '@cipherbox/crypto';
import { addToIpfs } from '../lib/api/ipfs';
import { createAndPublishIpnsRecord } from './ipns.service';
import type { FolderNode } from '../stores/folder.store';

/** Maximum folder nesting depth per FOLD-03 */
const MAX_FOLDER_DEPTH = 20;

/**
 * Calculate the depth of a folder from root.
 * Root folder has depth 0, immediate children have depth 1, etc.
 *
 * Used for enforcing FOLD-03 depth limit of 20.
 *
 * @param folderId - Folder ID to calculate depth for (null = root)
 * @param folders - Current folder tree
 * @returns Depth from root (0 for root)
 */
export function getDepth(folderId: string | null, folders: Record<string, FolderNode>): number {
  if (folderId === null) return 0; // root is depth 0

  let depth = 0;
  let currentId: string | null = folderId;

  while (currentId !== null) {
    const folder: FolderNode | undefined = folders[currentId];
    if (!folder) break;
    depth++;
    currentId = folder.parentId;
  }

  return depth;
}

/**
 * Load a folder's metadata from IPNS.
 *
 * For now, returns an empty folder structure. Actual metadata fetch
 * from IPFS and decryption will be implemented in Phase 05-04.
 *
 * @param folderId - Folder ID (null for root, or UUID)
 * @param folderKey - Decrypted AES-256 key for this folder
 * @param ipnsPrivateKey - Decrypted Ed25519 private key for IPNS
 * @param ipnsName - IPNS name for this folder
 */
export async function loadFolder(
  folderId: string | null,
  folderKey: Uint8Array,
  ipnsPrivateKey: Uint8Array,
  ipnsName: string
): Promise<FolderNode> {
  // TODO: Implement in 05-04
  // 1. Resolve IPNS to get current metadata CID (or use cached)
  // 2. Fetch encrypted metadata from IPFS gateway
  // 3. Decrypt with folderKey
  // 4. Return FolderNode with decrypted children

  // For now, return empty folder placeholder
  return {
    id: folderId ?? 'root',
    name: folderId ? 'Folder' : 'My Vault',
    ipnsName,
    parentId: null,
    children: [],
    isLoaded: true,
    isLoading: false,
    sequenceNumber: 0n,
    folderKey,
    ipnsPrivateKey,
  };
}

/**
 * Create a new subfolder with generated keys.
 *
 * Generates new Ed25519 IPNS keypair and AES-256 folder key,
 * wraps them with the user's public key for storage.
 *
 * @param params.parentFolderId - Parent folder ID (null for root)
 * @param params.name - Folder name
 * @param params.userPublicKey - User's secp256k1 public key for ECIES wrapping
 * @param params.folders - Current folder tree (for depth checking)
 * @returns Created folder entry and decrypted keys
 * @throws Error if depth limit exceeded (FOLD-03)
 */
export async function createFolder(params: {
  parentFolderId: string | null;
  name: string;
  userPublicKey: Uint8Array;
  folders: Record<string, FolderNode>;
}): Promise<{
  folder: FolderEntry;
  ipnsPrivateKey: Uint8Array;
  folderKey: Uint8Array;
}> {
  // 1. Check depth limit (FOLD-03)
  const parentDepth = getDepth(params.parentFolderId, params.folders);
  if (parentDepth >= MAX_FOLDER_DEPTH) {
    throw new Error(`Cannot create folder: maximum depth of ${MAX_FOLDER_DEPTH} exceeded`);
  }

  // 2. Generate Ed25519 keypair for folder IPNS
  const ipnsKeypair = await generateEd25519Keypair();
  const ipnsName = await deriveIpnsName(ipnsKeypair.publicKey);

  // 3. Generate random AES-256 folder key
  const folderKey = generateRandomBytes(32);

  // 4. Wrap keys with user's public key (ECIES encryption)
  // The 64-byte libp2p format private key (privateKey || publicKey) is wrapped
  const ipnsPrivateKeyEncrypted = bytesToHex(
    await wrapKey(ipnsKeypair.privateKey, params.userPublicKey)
  );
  const folderKeyEncrypted = bytesToHex(await wrapKey(folderKey, params.userPublicKey));

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

  return { folder, ipnsPrivateKey: ipnsKeypair.privateKey, folderKey };
}

/**
 * Update folder metadata and publish to IPNS.
 *
 * Encrypts the metadata with the folder key, uploads to IPFS,
 * and publishes an updated IPNS record pointing to the new CID.
 *
 * @param params.folderId - Folder being updated
 * @param params.children - New children array
 * @param params.folderKey - Decrypted AES-256 folder key
 * @param params.ipnsPrivateKey - Decrypted Ed25519 IPNS private key
 * @param params.ipnsName - IPNS name for this folder
 * @param params.sequenceNumber - Current sequence number
 * @param params.encryptedIpnsPrivateKey - TEE-wrapped key (first publish only)
 * @param params.keyEpoch - TEE key epoch (required with encryptedIpnsPrivateKey)
 * @returns New CID and sequence number
 */
export async function updateFolderMetadata(params: {
  folderId: string;
  children: FolderChild[];
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
}): Promise<{ cid: string; newSequenceNumber: bigint }> {
  // 1. Create folder metadata
  const metadata: FolderMetadata = {
    version: 'v1',
    children: params.children,
  };

  // 2. Encrypt metadata with folder key
  const encrypted = await encryptFolderMetadata(metadata, params.folderKey);

  // 3. Upload to IPFS via backend relay
  const blob = new Blob([JSON.stringify(encrypted)], {
    type: 'application/json',
  });
  const { cid } = await addToIpfs(blob);

  // 4. Publish IPNS record pointing to new CID
  const newSeq = params.sequenceNumber + 1n;
  await createAndPublishIpnsRecord({
    ipnsPrivateKey: params.ipnsPrivateKey,
    ipnsName: params.ipnsName,
    metadataCid: cid,
    sequenceNumber: newSeq,
    encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
    keyEpoch: params.keyEpoch,
  });

  return { cid, newSequenceNumber: newSeq };
}

/**
 * Rename a folder within its parent.
 *
 * Updates the folder entry's name in the parent's metadata and publishes
 * an updated IPNS record for the parent folder.
 *
 * @param params.folderId - ID of folder to rename
 * @param params.newName - New name for the folder
 * @param params.parentFolderState - Parent folder containing this folder
 * @throws Error if folder not found or name collision exists
 */
export async function renameFolder(params: {
  folderId: string;
  newName: string;
  parentFolderState: FolderNode;
}): Promise<void> {
  // 1. Find folder entry in parent's children
  const children = [...params.parentFolderState.children];
  const folderIndex = children.findIndex((c) => c.type === 'folder' && c.id === params.folderId);

  if (folderIndex === -1) throw new Error('Folder not found');

  // 2. Check for name collision
  const nameExists = children.some((c) => c.name === params.newName && c.id !== params.folderId);
  if (nameExists) throw new Error('An item with this name already exists');

  // 3. Update name and modifiedAt
  const folder = children[folderIndex] as FolderEntry;
  children[folderIndex] = {
    ...folder,
    name: params.newName,
    modifiedAt: Date.now(),
  };

  // 4. Update parent folder metadata and publish
  await updateFolderMetadata({
    folderId: params.parentFolderState.id,
    children,
    folderKey: params.parentFolderState.folderKey,
    ipnsPrivateKey: params.parentFolderState.ipnsPrivateKey,
    ipnsName: params.parentFolderState.ipnsName,
    sequenceNumber: params.parentFolderState.sequenceNumber,
  });
}

/**
 * Delete a folder and all its contents recursively.
 *
 * Collects all file CIDs from the folder and its subfolders,
 * removes the folder from the parent's metadata, publishes the update,
 * and unpins all file CIDs in the background.
 *
 * @param params.folderId - ID of folder to delete
 * @param params.parentFolderState - Parent folder containing this folder
 * @param params.getFolderState - Function to get folder state by ID (for recursion)
 * @param params.unpinCid - Function to unpin a CID from IPFS
 * @throws Error if folder not found
 */
export async function deleteFolder(params: {
  folderId: string;
  parentFolderState: FolderNode;
  getFolderState: (id: string) => FolderNode | undefined;
  unpinCid: (cid: string) => Promise<void>;
}): Promise<string[]> {
  // 1. Find folder in parent's children
  const children = [...params.parentFolderState.children];
  const folderIndex = children.findIndex((c) => c.type === 'folder' && c.id === params.folderId);

  if (folderIndex === -1) throw new Error('Folder not found');

  // 2. Recursively collect all CIDs to unpin (files in this folder and subfolders)
  const cidsToUnpin: string[] = [];
  const collectCids = (folderId: string) => {
    const folder = params.getFolderState(folderId);
    if (!folder) return;

    for (const child of folder.children) {
      if (child.type === 'file') {
        cidsToUnpin.push(child.cid);
      } else if (child.type === 'folder') {
        collectCids(child.id);
      }
    }
  };

  collectCids(params.folderId);

  // 3. Remove folder from parent's children
  children.splice(folderIndex, 1);

  // 4. Update parent folder metadata and publish
  await updateFolderMetadata({
    folderId: params.parentFolderState.id,
    children,
    folderKey: params.parentFolderState.folderKey,
    ipnsPrivateKey: params.parentFolderState.ipnsPrivateKey,
    ipnsName: params.parentFolderState.ipnsName,
    sequenceNumber: params.parentFolderState.sequenceNumber,
  });

  // 5. Unpin all collected CIDs (fire and forget, don't block)
  Promise.all(cidsToUnpin.map((cid) => params.unpinCid(cid).catch(() => {})));

  // Return CIDs for caller to track/log
  return cidsToUnpin;
}

/**
 * Delete a file from its parent folder.
 *
 * Removes the file from the parent's metadata, publishes the update,
 * and unpins the file CID in the background.
 *
 * Note: This handles folder metadata update. Use delete.service.ts deleteFile
 * for direct IPFS unpin with quota update.
 *
 * @param params.fileId - ID of file to delete
 * @param params.parentFolderState - Parent folder containing this file
 * @param params.unpinCid - Optional function to unpin a CID from IPFS
 * @throws Error if file not found
 */
export async function deleteFileFromFolder(params: {
  fileId: string;
  parentFolderState: FolderNode;
  unpinCid?: (cid: string) => Promise<void>;
}): Promise<void> {
  // 1. Find file in parent's children
  const children = [...params.parentFolderState.children];
  const fileIndex = children.findIndex((c) => c.type === 'file' && c.id === params.fileId);

  if (fileIndex === -1) throw new Error('File not found');

  // 2. Get file CID for unpinning
  const file = children[fileIndex] as FileEntry;
  const cidToUnpin = file.cid;

  // 3. Remove file from parent's children
  children.splice(fileIndex, 1);

  // 4. Update parent folder metadata and publish
  await updateFolderMetadata({
    folderId: params.parentFolderState.id,
    children,
    folderKey: params.parentFolderState.folderKey,
    ipnsPrivateKey: params.parentFolderState.ipnsPrivateKey,
    ipnsName: params.parentFolderState.ipnsName,
    sequenceNumber: params.parentFolderState.sequenceNumber,
  });

  // 5. Unpin file CID (fire and forget, don't block)
  if (params.unpinCid) {
    params.unpinCid(cidToUnpin).catch(() => {});
  }
}
