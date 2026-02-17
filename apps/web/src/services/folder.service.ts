/**
 * Folder Service - Folder CRUD operations with encryption (v2 metadata)
 *
 * Handles folder creation, loading, and metadata updates with
 * client-side encryption using @cipherbox/crypto.
 *
 * v2 metadata: Folders store slim FilePointer references instead of
 * inline FileEntry objects. File metadata lives in per-file IPNS records.
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
  createIpnsRecord,
  marshalIpnsRecord,
  type FolderMetadata,
  type FolderMetadataV2,
  type EncryptedFolderMetadata,
  type FolderEntry,
  type FolderChildV2,
  type FilePointer,
} from '@cipherbox/crypto';
import { addToIpfs, fetchFromIpfs } from '../lib/api/ipfs';
import { createAndPublishIpnsRecord, resolveIpnsRecord } from './ipns.service';
import { batchPublishIpnsRecords } from './ipns.service';
import { useAuthStore } from '../stores/auth.store';
import type { FolderNode } from '../stores/folder.store';
import type { FileIpnsRecordPayload } from './file-metadata.service';

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
 * Resolves the folder's IPNS name to get the current metadata CID,
 * fetches and decrypts the metadata, and returns a complete FolderNode.
 * Supports both v1 and v2 metadata formats (v2 children are FolderChildV2[]).
 *
 * IMPORTANT: Does NOT eagerly resolve per-file IPNS records during folder load.
 * File metadata is lazy-loaded on download/preview (Pitfall 1 from research).
 *
 * @param folderId - Folder ID (null for root, or UUID)
 * @param folderKey - Decrypted AES-256 key for this folder
 * @param ipnsPrivateKey - Decrypted Ed25519 private key for IPNS
 * @param ipnsName - IPNS name for this folder
 * @param parentId - Parent folder ID (null for root)
 * @param name - Display name for this folder
 */
export async function loadFolder(
  folderId: string | null,
  folderKey: Uint8Array,
  ipnsPrivateKey: Uint8Array,
  ipnsName: string,
  parentId: string | null,
  name: string
): Promise<FolderNode> {
  // 1. Resolve IPNS to get current metadata CID
  const resolved = await resolveIpnsRecord(ipnsName);

  // 2. If IPNS resolution returns null, return unloaded folder so it can be retried
  //    This handles newly-created subfolders whose IPNS hasn't propagated yet
  if (!resolved) {
    console.warn(
      `IPNS resolution returned null for folder "${name}" (${ipnsName}). Marking as not loaded for retry.`
    );
    return {
      id: folderId ?? 'root',
      name,
      ipnsName,
      parentId,
      children: [],
      isLoaded: false,
      isLoading: false,
      sequenceNumber: 0n,
      folderKey,
      ipnsPrivateKey,
    };
  }

  // 3. Fetch encrypted metadata from IPFS and decrypt with folderKey
  const metadata = await fetchAndDecryptMetadata(resolved.cid, folderKey);

  // 4. Return complete FolderNode with decrypted children
  // Both v1 and v2 children are stored as FolderChildV2[] in the store.
  // v1 FileEntry objects won't exist after the clean break (DB wipe).
  // v2 FilePointer objects have fileMetaIpnsName instead of inline file data.
  return {
    id: folderId ?? 'root',
    name,
    ipnsName,
    parentId,
    children: metadata.children as FolderChildV2[],
    isLoaded: true,
    isLoading: false,
    sequenceNumber: resolved.sequenceNumber,
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
 * Update folder metadata and publish to IPNS (v2 format).
 *
 * Encrypts the metadata with the folder key, uploads to IPFS,
 * and publishes an updated IPNS record pointing to the new CID.
 *
 * @param params.folderId - Folder being updated
 * @param params.children - New children array (FolderChildV2[])
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
  children: FolderChildV2[];
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
}): Promise<{ cid: string; newSequenceNumber: bigint }> {
  // 1. Create v2 folder metadata
  const metadata: FolderMetadataV2 = {
    version: 'v2',
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
 * Build a folder IPNS record payload for batch publishing.
 *
 * Creates and signs an IPNS record locally without publishing.
 * Returns the payload that can be included in a batch publish call.
 *
 * @returns Folder IPNS record payload for batch publish
 */
async function buildFolderIpnsRecord(params: {
  children: FolderChildV2[];
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
}): Promise<{
  cid: string;
  record: FileIpnsRecordPayload & { recordType: 'folder' };
  newSequenceNumber: bigint;
}> {
  // 1. Create v2 folder metadata
  const metadata: FolderMetadataV2 = {
    version: 'v2',
    children: params.children,
  };

  // 2. Encrypt metadata with folder key
  const encrypted = await encryptFolderMetadata(metadata, params.folderKey);

  // 3. Upload to IPFS
  const blob = new Blob([JSON.stringify(encrypted)], { type: 'application/json' });
  const { cid } = await addToIpfs(blob);

  // 4. Create IPNS record
  const newSeq = params.sequenceNumber + 1n;
  const record = await createIpnsRecord(
    params.ipnsPrivateKey,
    `/ipfs/${cid}`,
    newSeq,
    24 * 60 * 60 * 1000
  );
  const recordBytes = marshalIpnsRecord(record);
  const recordBase64 = btoa(String.fromCharCode(...recordBytes));

  return {
    cid,
    record: {
      ipnsName: params.ipnsName,
      recordBase64,
      metadataCid: cid,
      encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
      keyEpoch: params.keyEpoch,
      recordType: 'folder',
    },
    newSequenceNumber: newSeq,
  };
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
 * For v2 metadata: collects fileMetaIpnsName values from FilePointer children
 * (not CIDs, since CIDs live in per-file IPNS records, not folder metadata).
 * Removes the folder from the parent's metadata, publishes the update.
 * Returns the collected file IPNS names so the caller can resolve them for
 * CID unpinning and TEE unenrollment.
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

  // 2. Recursively collect file IPNS names for cleanup
  // In v2, file children are FilePointers with fileMetaIpnsName (no inline CID).
  // The caller must resolve each fileMetaIpnsName to get the CID for unpinning.
  const fileIpnsNames: string[] = [];
  const collectFileIpnsNames = (folderId: string) => {
    const folder = params.getFolderState(folderId);
    if (!folder) return;

    for (const child of folder.children) {
      if (child.type === 'file') {
        const filePointer = child as FilePointer;
        if (filePointer.fileMetaIpnsName) {
          fileIpnsNames.push(filePointer.fileMetaIpnsName);
        }
      } else if (child.type === 'folder') {
        collectFileIpnsNames(child.id);
      }
    }
  };

  collectFileIpnsNames(params.folderId);

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

  // 5. File CID unpinning and TEE unenrollment deferred to caller
  // The caller (useFolder hook) resolves fileMetaIpnsName -> CID for unpinning.
  // TODO: Phase 14 should add batch unenrollment for orphaned file IPNS records.

  return fileIpnsNames;
}

/**
 * Delete a file from its parent folder (v2).
 *
 * Removes the FilePointer from the parent's metadata, publishes the update.
 * Returns the fileMetaIpnsName so the caller can resolve it for CID unpinning
 * and TEE unenrollment.
 *
 * Note: This handles folder metadata update. File CID unpinning is handled
 * by the caller after resolving the file metadata.
 *
 * @param params.fileId - ID of file to delete
 * @param params.parentFolderState - Parent folder containing this file
 * @returns fileMetaIpnsName for caller to handle cleanup
 * @throws Error if file not found
 */
export async function deleteFileFromFolder(params: {
  fileId: string;
  parentFolderState: FolderNode;
}): Promise<{ fileMetaIpnsName: string | undefined }> {
  // 1. Find file in parent's children
  const children = [...params.parentFolderState.children];
  const fileIndex = children.findIndex((c) => c.type === 'file' && c.id === params.fileId);

  if (fileIndex === -1) throw new Error('File not found');

  // 2. Get fileMetaIpnsName for cleanup
  const filePointer = children[fileIndex] as FilePointer;
  const fileMetaIpnsName = filePointer.fileMetaIpnsName;

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

  // 5. TEE unenrollment: no API endpoint available yet.
  // TODO: Phase 14 should expose unenrollIpns via REST API.
  if (fileMetaIpnsName) {
    console.warn(
      `File IPNS record ${fileMetaIpnsName} orphaned after deletion. TEE unenrollment deferred to Phase 14.`
    );
  }

  return { fileMetaIpnsName };
}

/**
 * Add a file to a folder after successful upload (v2).
 *
 * Creates a FilePointer from the file's IPNS record and adds it to the folder's
 * children array. Publishes both the file IPNS record and the updated folder
 * metadata via a single batch API call.
 *
 * @param params.parentFolderState - Parent folder to add file to
 * @param params.fileId - Pre-generated file UUID
 * @param params.name - Original file name
 * @param params.fileIpnsRecord - File IPNS record payload from createFileMetadata
 * @returns Created file pointer and new sequence number
 * @throws Error if name collision exists
 */
export async function addFileToFolder(params: {
  parentFolderState: FolderNode;
  fileId: string;
  name: string;
  fileIpnsRecord: FileIpnsRecordPayload;
}): Promise<{ filePointer: FilePointer; newSequenceNumber: bigint }> {
  // 1. Check for name collision
  const nameExists = params.parentFolderState.children.some((c) => c.name === params.name);
  if (nameExists) {
    throw new Error('A file with this name already exists');
  }

  // 2. Create FilePointer (slim reference to per-file IPNS record)
  const now = Date.now();
  const filePointer: FilePointer = {
    type: 'file',
    id: params.fileId,
    name: params.name,
    fileMetaIpnsName: params.fileIpnsRecord.ipnsName,
    createdAt: now,
    modifiedAt: now,
  };

  // 3. Add FilePointer to parent's children
  const children: FolderChildV2[] = [...params.parentFolderState.children, filePointer];

  // 4. Build folder IPNS record for batch publish
  const folderResult = await buildFolderIpnsRecord({
    children,
    folderKey: params.parentFolderState.folderKey,
    ipnsPrivateKey: params.parentFolderState.ipnsPrivateKey,
    ipnsName: params.parentFolderState.ipnsName,
    sequenceNumber: params.parentFolderState.sequenceNumber,
  });

  // 5. Batch publish: file IPNS record + folder IPNS record
  await batchPublishIpnsRecords([
    { ...params.fileIpnsRecord, recordType: 'file' },
    folderResult.record,
  ]);

  return { filePointer, newSequenceNumber: folderResult.newSequenceNumber };
}

/**
 * Add multiple files to a folder after successful upload (v2 batch).
 *
 * Creates FilePointer objects for all files, checks for name collisions,
 * then publishes all N file IPNS records + 1 folder IPNS record via a
 * single batch API call.
 *
 * @param params.parentFolderState - Parent folder to add files to
 * @param params.files - Array of file data with pre-created IPNS records
 * @returns Created file pointers and new sequence number
 * @throws Error if any name collision exists
 */
export async function addFilesToFolder(params: {
  parentFolderState: FolderNode;
  files: Array<{
    fileId: string;
    name: string;
    fileIpnsRecord: FileIpnsRecordPayload;
  }>;
}): Promise<{ filePointers: FilePointer[]; newSequenceNumber: bigint }> {
  // 1. Build a set of existing child names for collision detection
  const existingNames = new Set(params.parentFolderState.children.map((c) => c.name));

  // 2. Create FilePointer for each file, checking collisions
  const filePointers: FilePointer[] = [];
  const now = Date.now();

  for (const file of params.files) {
    if (existingNames.has(file.name)) {
      throw new Error(`A file with name "${file.name}" already exists`);
    }
    existingNames.add(file.name);

    const filePointer: FilePointer = {
      type: 'file',
      id: file.fileId,
      name: file.name,
      fileMetaIpnsName: file.fileIpnsRecord.ipnsName,
      createdAt: now,
      modifiedAt: now,
    };
    filePointers.push(filePointer);
  }

  // 3. Build updated children array
  const children: FolderChildV2[] = [...params.parentFolderState.children, ...filePointers];

  // 4. Build folder IPNS record
  const folderResult = await buildFolderIpnsRecord({
    children,
    folderKey: params.parentFolderState.folderKey,
    ipnsPrivateKey: params.parentFolderState.ipnsPrivateKey,
    ipnsName: params.parentFolderState.ipnsName,
    sequenceNumber: params.parentFolderState.sequenceNumber,
  });

  // 5. Batch publish: all N file IPNS records + 1 folder IPNS record (single API call)
  const allRecords = [
    ...params.files.map((f) => ({ ...f.fileIpnsRecord, recordType: 'file' as const })),
    folderResult.record,
  ];
  await batchPublishIpnsRecords(allRecords);

  return { filePointers, newSequenceNumber: folderResult.newSequenceNumber };
}

/**
 * Replace file content in v2 metadata (content update).
 *
 * THIS IS THE PRIMARY BENEFIT OF PER-FILE IPNS: content updates publish
 * ONLY the file's IPNS record. The folder metadata is NOT touched because
 * the FilePointer still points to the same fileMetaIpnsName, which now
 * resolves to the updated content.
 *
 * @param params.fileId - ID of file to update
 * @param params.fileIpnsRecord - Updated file IPNS record from updateFileMetadata
 * @param params.parentFolderState - Parent folder (used only to find the FilePointer)
 * @returns Void -- no folder metadata update needed
 * @throws Error if file not found
 */
export async function replaceFileInFolder(params: {
  fileId: string;
  fileIpnsRecord: FileIpnsRecordPayload;
  parentFolderState: FolderNode;
}): Promise<void> {
  // 1. Verify file exists in parent's children
  const fileExists = params.parentFolderState.children.some(
    (c) => c.type === 'file' && c.id === params.fileId
  );

  if (!fileExists) throw new Error('File not found');

  // 2. Publish ONLY the file IPNS record (folder metadata untouched!)
  // This is the key optimization: content update does NOT modify folder metadata.
  await batchPublishIpnsRecords([{ ...params.fileIpnsRecord, recordType: 'file' }]);
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
  const destChildren: FolderChildV2[] = [
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
 * Move a file from one folder to another (v2).
 *
 * Uses add-before-remove pattern to prevent data loss on failure.
 * FilePointer contains fileMetaIpnsName which stays the same across moves --
 * no file IPNS record changes needed, only folder metadata changes.
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
  // 1. Find file in source (v2: FilePointer)
  const file = params.sourceFolderState.children.find(
    (c) => c.type === 'file' && c.id === params.fileId
  ) as FilePointer | undefined;

  if (!file) throw new Error('File not found');

  // 2. Check name collision in destination
  const nameExists = params.destFolderState.children.some((c) => c.name === file.name);
  if (nameExists) throw new Error('An item with this name already exists in destination');

  // 3. ADD to destination FIRST
  const destChildren: FolderChildV2[] = [
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
 * Rename a file within its parent folder (v2).
 *
 * Updates the FilePointer's name in the parent's metadata and publishes
 * an updated IPNS record for the parent folder.
 * File rename does NOT touch the file's own IPNS record -- only folder metadata.
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

  const file = children[fileIndex] as FilePointer;
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
 * Returns either v1 or v2 metadata depending on the encrypted content.
 *
 * @param cid - IPFS CID of the encrypted metadata blob
 * @param folderKey - Decrypted AES-256 folder key
 * @returns Decrypted folder metadata (v1 or v2)
 * @throws Error if fetch or decryption fails
 */
export async function fetchAndDecryptMetadata(
  cid: string,
  folderKey: Uint8Array
): Promise<FolderMetadata | FolderMetadataV2> {
  // 1. Fetch encrypted metadata blob from IPFS
  const encryptedBytes = await fetchFromIpfs(cid);

  // 2. Parse as JSON to get EncryptedFolderMetadata (contains iv and data fields)
  const encryptedJson = new TextDecoder().decode(encryptedBytes);
  const encrypted: EncryptedFolderMetadata = JSON.parse(encryptedJson);

  // 3. Decrypt using folder key (returns v1 or v2 depending on content)
  const metadata = await decryptFolderMetadata(encrypted, folderKey);

  return metadata;
}
