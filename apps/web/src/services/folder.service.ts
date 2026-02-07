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
  hexToBytes,
  encryptFolderMetadata,
  decryptFolderMetadata,
  type FolderMetadata,
  type EncryptedFolderMetadata,
  type FolderEntry,
  type FileEntry,
  type FolderChild,
} from '@cipherbox/crypto';
import { addToIpfs, fetchFromIpfs } from '../lib/api/ipfs';
import { createAndPublishIpnsRecord } from './ipns.service';
import { useAuthStore } from '../stores/auth.store';
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
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
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

  // 5. TEE-02: Encrypt IPNS private key with TEE public key for republishing
  let encryptedIpnsPrivateKey: string | undefined;
  let keyEpoch: number | undefined;

  const teeKeys = useAuthStore.getState().teeKeys;
  if (teeKeys?.currentPublicKey) {
    const teePublicKey = hexToBytes(teeKeys.currentPublicKey);
    const encryptedKey = await wrapKey(ipnsKeypair.privateKey, teePublicKey);
    encryptedIpnsPrivateKey = bytesToHex(encryptedKey);
    keyEpoch = teeKeys.currentEpoch;
  }

  // 6. Create folder entry for parent's metadata
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

/**
 * Add a file to a folder after successful upload.
 *
 * Creates a FileEntry from the upload result and adds it to the folder's
 * children array, then publishes the updated metadata to IPNS.
 *
 * @param params.parentFolderState - Parent folder to add file to
 * @param params.cid - IPFS CID of the encrypted file
 * @param params.fileKeyEncrypted - Hex-encoded ECIES-wrapped file key
 * @param params.fileIv - Hex-encoded IV used for encryption
 * @param params.name - Original file name
 * @param params.size - Original file size in bytes
 * @returns Created file entry and new sequence number
 * @throws Error if name collision exists
 */
export async function addFileToFolder(params: {
  parentFolderState: FolderNode;
  cid: string;
  fileKeyEncrypted: string;
  fileIv: string;
  name: string;
  size: number;
}): Promise<{ fileEntry: FileEntry; newSequenceNumber: bigint }> {
  // 1. Check for name collision
  const nameExists = params.parentFolderState.children.some((c) => c.name === params.name);
  if (nameExists) {
    throw new Error('A file with this name already exists');
  }

  // 2. Create file entry
  const now = Date.now();
  const fileEntry: FileEntry = {
    type: 'file',
    id: crypto.randomUUID(),
    name: params.name,
    cid: params.cid,
    fileKeyEncrypted: params.fileKeyEncrypted,
    fileIv: params.fileIv,
    encryptionMode: 'GCM',
    size: params.size,
    createdAt: now,
    modifiedAt: now,
  };

  // 3. Add to parent's children
  const children = [...params.parentFolderState.children, fileEntry];

  // 4. Update parent folder metadata and publish IPNS
  const { newSequenceNumber } = await updateFolderMetadata({
    folderId: params.parentFolderState.id,
    children,
    folderKey: params.parentFolderState.folderKey,
    ipnsPrivateKey: params.parentFolderState.ipnsPrivateKey,
    ipnsName: params.parentFolderState.ipnsName,
    sequenceNumber: params.parentFolderState.sequenceNumber,
  });

  return { fileEntry, newSequenceNumber };
}

/**
 * Add multiple files to a folder after successful upload (batch).
 *
 * Creates FileEntry objects for all files, checks for name collisions
 * (against existing children AND within the batch), then updates folder
 * metadata and publishes IPNS exactly once for the entire batch.
 *
 * @param params.parentFolderState - Parent folder to add files to
 * @param params.files - Array of uploaded file data
 * @returns Created file entries and new sequence number
 * @throws Error if any name collision exists (within folder or within batch)
 */
export async function addFilesToFolder(params: {
  parentFolderState: FolderNode;
  files: Array<{
    cid: string;
    fileKeyEncrypted: string;
    fileIv: string;
    name: string;
    size: number;
  }>;
}): Promise<{ fileEntries: FileEntry[]; newSequenceNumber: bigint }> {
  // 1. Build a set of existing child names for collision detection
  const existingNames = new Set(params.parentFolderState.children.map((c) => c.name));

  // 2. Create FileEntry for each file, checking collisions
  const fileEntries: FileEntry[] = [];
  const now = Date.now();

  for (const file of params.files) {
    // Check collision against existing children AND previously added batch files
    if (existingNames.has(file.name)) {
      throw new Error(`A file with name "${file.name}" already exists`);
    }
    existingNames.add(file.name);

    const fileEntry: FileEntry = {
      type: 'file',
      id: crypto.randomUUID(),
      name: file.name,
      cid: file.cid,
      fileKeyEncrypted: file.fileKeyEncrypted,
      fileIv: file.fileIv,
      encryptionMode: 'GCM',
      size: file.size,
      createdAt: now,
      modifiedAt: now,
    };
    fileEntries.push(fileEntry);
  }

  // 3. Build updated children array
  const children = [...params.parentFolderState.children, ...fileEntries];

  // 4. Update folder metadata and publish IPNS (single publish for entire batch)
  const { newSequenceNumber } = await updateFolderMetadata({
    folderId: params.parentFolderState.id,
    children,
    folderKey: params.parentFolderState.folderKey,
    ipnsPrivateKey: params.parentFolderState.ipnsPrivateKey,
    ipnsName: params.parentFolderState.ipnsName,
    sequenceNumber: params.parentFolderState.sequenceNumber,
  });

  return { fileEntries, newSequenceNumber };
}

/**
 * Calculate the maximum depth of a folder's subtree.
 *
 * Used to check if moving a folder would exceed the depth limit.
 *
 * @param folderId - Folder ID to calculate subtree depth for
 * @param folders - Current folder tree
 * @returns Maximum depth in the subtree (0 if folder has no children)
 */
export function calculateSubtreeDepth(
  folderId: string,
  folders: Record<string, FolderNode>
): number {
  const folder = folders[folderId];
  if (!folder) return 0;

  let maxChildDepth = 0;
  for (const child of folder.children) {
    if (child.type === 'folder') {
      const childDepth = 1 + calculateSubtreeDepth(child.id, folders);
      maxChildDepth = Math.max(maxChildDepth, childDepth);
    }
  }

  return maxChildDepth;
}

/**
 * Check if a folder is a descendant of a potential ancestor.
 *
 * Used to prevent moving a folder into itself or its descendants.
 *
 * @param folderId - Folder to check
 * @param potentialAncestorId - Potential ancestor folder ID
 * @param folders - Current folder tree
 * @returns true if folderId is a descendant of potentialAncestorId
 */
export function isDescendantOf(
  folderId: string,
  potentialAncestorId: string,
  folders: Record<string, FolderNode>
): boolean {
  let currentId: string | null = folderId;

  while (currentId !== null) {
    if (currentId === potentialAncestorId) return true;
    const currentFolder: FolderNode | undefined = folders[currentId];
    if (!currentFolder) break;
    currentId = currentFolder.parentId;
  }

  return false;
}

/**
 * Move a folder from one parent to another.
 *
 * Uses add-before-remove pattern to prevent data loss on failure.
 * Validates depth limit and prevents moving folder into itself.
 *
 * @param params.folderId - ID of folder to move
 * @param params.sourceFolderState - Current parent folder
 * @param params.destFolderState - Destination parent folder
 * @param params.folders - Full folder tree (for depth calculation)
 * @throws Error if folder not found, name collision, depth limit exceeded,
 *         or attempting to move folder into itself/descendant
 */
export async function moveFolder(params: {
  folderId: string;
  sourceFolderState: FolderNode;
  destFolderState: FolderNode;
  folders: Record<string, FolderNode>;
}): Promise<void> {
  // 1. Find folder in source
  const folder = params.sourceFolderState.children.find(
    (c) => c.type === 'folder' && c.id === params.folderId
  ) as FolderEntry | undefined;

  if (!folder) throw new Error('Folder not found');

  // 2. Check name collision in destination
  const nameExists = params.destFolderState.children.some((c) => c.name === folder.name);
  if (nameExists) throw new Error('An item with this name already exists in destination');

  // 3. Check depth limit (20 levels max)
  const destDepth = getDepth(params.destFolderState.id, params.folders);
  const folderSubtreeDepth = calculateSubtreeDepth(params.folderId, params.folders);
  if (destDepth + 1 + folderSubtreeDepth > MAX_FOLDER_DEPTH) {
    throw new Error(`Cannot move: would exceed maximum folder depth of ${MAX_FOLDER_DEPTH}`);
  }

  // 4. Prevent moving folder into itself or its descendants
  if (isDescendantOf(params.destFolderState.id, params.folderId, params.folders)) {
    throw new Error('Cannot move folder into itself or its subfolder');
  }

  // 5. ADD to destination FIRST (add-before-remove pattern)
  const destChildren = [
    ...params.destFolderState.children,
    {
      ...folder,
      modifiedAt: Date.now(),
    },
  ];

  await updateFolderMetadata({
    folderId: params.destFolderState.id,
    children: destChildren,
    folderKey: params.destFolderState.folderKey,
    ipnsPrivateKey: params.destFolderState.ipnsPrivateKey,
    ipnsName: params.destFolderState.ipnsName,
    sequenceNumber: params.destFolderState.sequenceNumber,
  });

  // 6. REMOVE from source AFTER destination confirmed
  const sourceChildren = params.sourceFolderState.children.filter(
    (c) => !(c.type === 'folder' && c.id === params.folderId)
  );

  await updateFolderMetadata({
    folderId: params.sourceFolderState.id,
    children: sourceChildren,
    folderKey: params.sourceFolderState.folderKey,
    ipnsPrivateKey: params.sourceFolderState.ipnsPrivateKey,
    ipnsName: params.sourceFolderState.ipnsName,
    sequenceNumber: params.sourceFolderState.sequenceNumber,
  });
}

/**
 * Move a file from one folder to another.
 *
 * Uses add-before-remove pattern to prevent data loss on failure.
 *
 * @param params.fileId - ID of file to move
 * @param params.sourceFolderState - Current parent folder
 * @param params.destFolderState - Destination folder
 * @throws Error if file not found or name collision exists
 */
export async function moveFile(params: {
  fileId: string;
  sourceFolderState: FolderNode;
  destFolderState: FolderNode;
}): Promise<void> {
  // 1. Find file in source
  const file = params.sourceFolderState.children.find(
    (c) => c.type === 'file' && c.id === params.fileId
  ) as FileEntry | undefined;

  if (!file) throw new Error('File not found');

  // 2. Check name collision in destination
  const nameExists = params.destFolderState.children.some((c) => c.name === file.name);
  if (nameExists) throw new Error('An item with this name already exists in destination');

  // 3. ADD to destination FIRST
  const destChildren = [
    ...params.destFolderState.children,
    {
      ...file,
      modifiedAt: Date.now(),
    },
  ];

  await updateFolderMetadata({
    folderId: params.destFolderState.id,
    children: destChildren,
    folderKey: params.destFolderState.folderKey,
    ipnsPrivateKey: params.destFolderState.ipnsPrivateKey,
    ipnsName: params.destFolderState.ipnsName,
    sequenceNumber: params.destFolderState.sequenceNumber,
  });

  // 4. REMOVE from source AFTER
  const sourceChildren = params.sourceFolderState.children.filter(
    (c) => !(c.type === 'file' && c.id === params.fileId)
  );

  await updateFolderMetadata({
    folderId: params.sourceFolderState.id,
    children: sourceChildren,
    folderKey: params.sourceFolderState.folderKey,
    ipnsPrivateKey: params.sourceFolderState.ipnsPrivateKey,
    ipnsName: params.sourceFolderState.ipnsName,
    sequenceNumber: params.sourceFolderState.sequenceNumber,
  });
}

/**
 * Rename a file within its parent folder.
 *
 * Updates the file entry's name in the parent's metadata and publishes
 * an updated IPNS record for the parent folder.
 *
 * @param params.fileId - ID of file to rename
 * @param params.newName - New name for the file
 * @param params.parentFolderState - Parent folder containing this file
 * @throws Error if file not found or name collision exists
 */
export async function renameFile(params: {
  fileId: string;
  newName: string;
  parentFolderState: FolderNode;
}): Promise<void> {
  const children = [...params.parentFolderState.children];
  const fileIndex = children.findIndex((c) => c.type === 'file' && c.id === params.fileId);

  if (fileIndex === -1) throw new Error('File not found');

  // Check name collision
  const nameExists = children.some((c) => c.name === params.newName && c.id !== params.fileId);
  if (nameExists) throw new Error('An item with this name already exists');

  const file = children[fileIndex] as FileEntry;
  children[fileIndex] = {
    ...file,
    name: params.newName,
    modifiedAt: Date.now(),
  };

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
 * Fetch and decrypt folder metadata from IPFS.
 *
 * Used for sync operations when remote IPNS resolves to a different CID.
 * Fetches the encrypted metadata blob from IPFS and decrypts it with the folder key.
 *
 * @param cid - IPFS CID of the encrypted metadata blob
 * @param folderKey - Decrypted AES-256 folder key
 * @returns Decrypted folder metadata (version and children array)
 * @throws Error if fetch or decryption fails
 */
export async function fetchAndDecryptMetadata(
  cid: string,
  folderKey: Uint8Array
): Promise<FolderMetadata> {
  // 1. Fetch encrypted metadata blob from IPFS
  const encryptedBytes = await fetchFromIpfs(cid);

  // 2. Parse as JSON to get EncryptedFolderMetadata (contains iv and data fields)
  const encryptedJson = new TextDecoder().decode(encryptedBytes);
  const encrypted: EncryptedFolderMetadata = JSON.parse(encryptedJson);

  // 3. Decrypt using folder key
  const metadata = await decryptFolderMetadata(encrypted, folderKey);

  return metadata;
}
