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
  deriveEd25519PublicKey,
  generateRandomBytes,
  wrapKey,
  bytesToHex,
  hexToBytes,
} from '@cipherbox/crypto';
import {
  encryptFolderMetadata,
  decryptFolderMetadata,
  createIpnsRecord,
  marshalIpnsRecord,
  type FolderMetadata,
  type EncryptedFolderMetadata,
  type FolderEntry,
  type FolderChild,
  type FilePointer,
} from '@cipherbox/core';
import type { SdkContext, TeeKeys } from '../types';
import { addToIpfs, fetchFromIpfs } from '../ipfs';
import { createAndPublishIpnsRecord, batchPublishIpnsRecords, resolveIpnsRecord } from '../ipns';
import { withPerf } from '../perf';
import type { FileIpnsRecordPayload } from '../file';
import { ConflictError } from '../errors';

// [ASSUMED] Exponential backoff constants for the 409 retry loop (A1 — values reasoned, not spec)
const BACKOFF_BASE_MS = 100;
const BACKOFF_CAP_MS = 1500;

/** Exponential backoff with ±50% jitter. */
function retryDelayMs(attempt: number): number {
  return Math.min(BACKOFF_BASE_MS * 2 ** attempt, BACKOFF_CAP_MS) * (0.5 + Math.random() * 0.5);
}

// Tree traversal utilities
export { getDepth, calculateSubtreeDepth, isDescendantOf, type TreeNode } from './tree';
import { mergeChildren } from './merge';
export { mergeChildren };

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
  return withPerf('folder:fetch-decrypt', async () => {
    const encryptedBytes = await fetchFromIpfs(ctx, cid);

    // All folder metadata (including root) is v1 JSON {iv, data}.
    // v2 blob format is only for the vault key blob (separate IPNS name).
    const encryptedJson = new TextDecoder().decode(encryptedBytes);
    const encrypted: EncryptedFolderMetadata = JSON.parse(encryptedJson);
    return decryptFolderMetadata(encrypted, folderKey);
  });
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
  return withPerf('folder:load', async () => {
    const resolved = await resolveIpnsRecord(params.ipnsName, params.ctx);
    if (!resolved) return null;

    const metadata = await fetchAndDecryptMetadata(resolved.cid, params.folderKey, params.ctx);

    return {
      metadata,
      sequenceNumber: resolved.sequenceNumber,
      cid: resolved.cid,
    };
  });
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
  baseChildren?: FolderChild[];
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsPublicKey?: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  ctx: SdkContext;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
}): Promise<{ cid: string; newSequenceNumber: bigint }> {
  return withPerf('folder:update-publish', async () => {
    // Merge-and-republish retry loop (D-01 through D-05).
    // encrypt+upload happens inside the loop so each attempt gets a fresh CID (D-03).
    let currentSeq = params.sequenceNumber;
    let currentLocalChildren: FolderChild[] = params.children;
    let lastRemoteSeq: bigint = params.sequenceNumber;

    for (let attempt = 0; attempt < 4; attempt++) {
      // 1. Build v2 metadata with current children, encrypt, upload → fresh CID (D-03)
      const metadata: FolderMetadata = {
        version: 'v2',
        children: currentLocalChildren,
      };
      const encrypted = await encryptFolderMetadata(metadata, params.folderKey);
      const jsonStr = JSON.stringify(encrypted);
      const encryptedBytes = new TextEncoder().encode(jsonStr);
      const { cid } = await addToIpfs(params.ctx, encryptedBytes);

      // 2. CAS publish: expectedSequenceNumber guards against lost update
      const newSeq = currentSeq + 1n;
      try {
        await createAndPublishIpnsRecord({
          ipnsPrivateKey: params.ipnsPrivateKey,
          ipnsPublicKey: params.ipnsPublicKey,
          ipnsName: params.ipnsName,
          metadataCid: cid,
          sequenceNumber: newSeq,
          encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
          keyEpoch: params.keyEpoch,
          expectedSequenceNumber: currentSeq.toString(),
          ctx: params.ctx,
        });
        return { cid, newSequenceNumber: newSeq };
      } catch (err) {
        const is409 =
          (err as Error & { status?: number }).status === 409 ||
          (err as Error & { response?: { status?: number } }).response?.status === 409;
        if (!is409) throw err;

        // 3. Re-resolve authoritatively — ignore any seq hint in the error body (Pitfall 1+2)
        const resolved = await resolveIpnsRecord(params.ipnsName, params.ctx);
        if (!resolved) {
          throw new ConflictError(params.ipnsName, attempt + 1, lastRemoteSeq);
        }
        currentSeq = resolved.sequenceNumber;
        lastRemoteSeq = resolved.sequenceNumber;

        // 4. Re-fetch + decrypt remote folder metadata
        const remote = await fetchAndDecryptMetadata(resolved.cid, params.folderKey, params.ctx);

        // 5. Three-way merge (D-01 / D-02)
        if (params.baseChildren !== undefined) {
          // D-01: caller provided base snapshot → proper three-way merge
          currentLocalChildren = mergeChildren(
            params.baseChildren,
            currentLocalChildren,
            remote.children
          );
        } else {
          // D-02: no base → union fallback; log warning so the caller sweep is noticeable
          console.warn(
            '[sdk-core] updateFolderMetadataAndPublish: baseChildren not provided for ' +
              params.ipnsName +
              ' — using union fallback (deletes may resurrect). Caller should pass baseChildren.'
          );
          currentLocalChildren = mergeChildren([], currentLocalChildren, remote.children);
        }

        // 6. After the final attempt, throw ConflictError (D-05)
        if (attempt === 3) {
          throw new ConflictError(params.ipnsName, 4, lastRemoteSeq);
        }

        // 7. Backoff + jitter before next attempt (D-04)
        await new Promise<void>((resolve) => setTimeout(resolve, retryDelayMs(attempt)));
      }
    }

    // Unreachable fallback (TypeScript exhaustion — ConflictError thrown inside the loop above)
    throw new ConflictError(params.ipnsName, 4, lastRemoteSeq);
  });
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

// ---------------------------------------------------------------------------
// File registration helpers (batch IPNS publish)
// ---------------------------------------------------------------------------

/** Safe base64 encoding that avoids call stack overflow from spread operator */
function uint8ToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Build a folder IPNS record payload for batch publishing.
 *
 * Creates and signs an IPNS record locally without publishing.
 * Returns the payload for inclusion in a batch publish call.
 */
async function buildFolderIpnsRecord(params: {
  children: FolderChild[];
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsPublicKey?: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  ctx: SdkContext;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
}): Promise<{
  cid: string;
  record: FileIpnsRecordPayload & { recordType: 'folder'; expectedSequenceNumber: string };
  newSequenceNumber: bigint;
}> {
  const metadata: FolderMetadata = {
    version: 'v2',
    children: params.children,
  };

  const encrypted = await encryptFolderMetadata(metadata, params.folderKey);
  const jsonStr = JSON.stringify(encrypted);
  const encryptedBytes = new TextEncoder().encode(jsonStr);
  const { cid } = await addToIpfs(params.ctx, encryptedBytes);

  const newSeq = params.sequenceNumber + 1n;
  const record = await createIpnsRecord(
    params.ipnsPrivateKey,
    `/ipfs/${cid}`,
    newSeq,
    24 * 60 * 60 * 1000
  );
  const recordBytes = marshalIpnsRecord(record);
  const recordBase64 = uint8ToBase64(recordBytes);
  const publicKey = uint8ToBase64(
    params.ipnsPublicKey ?? deriveEd25519PublicKey(params.ipnsPrivateKey)
  );

  return {
    cid,
    record: {
      ipnsName: params.ipnsName,
      recordBase64,
      publicKey,
      metadataCid: cid,
      encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
      keyEpoch: params.keyEpoch,
      recordType: 'folder',
      expectedSequenceNumber: params.sequenceNumber.toString(),
    },
    newSequenceNumber: newSeq,
  };
}

/**
 * Add a single file to a folder and batch-publish both IPNS records.
 *
 * Creates a FilePointer, builds a folder IPNS record, and publishes
 * both the file and folder IPNS records in a single batch API call.
 *
 * @returns Created file pointer and new folder sequence number
 * @throws Error if name collision exists or batch publish fails
 */
export async function addFileToFolder(params: {
  children: FolderChild[];
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsPublicKey?: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  fileId: string;
  name: string;
  fileIpnsRecord: FileIpnsRecordPayload;
  ipnsPrivateKeyEncrypted: string;
  ctx: SdkContext;
}): Promise<{ filePointer: FilePointer; newSequenceNumber: bigint }> {
  // 1. Check for name collision
  const nameExists = params.children.some((c) => c.name === params.name);
  if (nameExists) {
    throw new Error('A file with this name already exists');
  }

  // 2. Create FilePointer
  const now = Date.now();
  const filePointer: FilePointer = {
    type: 'file',
    id: params.fileId,
    name: params.name,
    fileMetaIpnsName: params.fileIpnsRecord.ipnsName,
    ipnsPrivateKeyEncrypted: params.ipnsPrivateKeyEncrypted,
    createdAt: now,
    modifiedAt: now,
  };

  // 3. Add FilePointer to parent's children
  const children: FolderChild[] = [...params.children, filePointer];

  // 4. Build folder IPNS record for batch publish
  const folderResult = await buildFolderIpnsRecord({
    children,
    folderKey: params.folderKey,
    ipnsPrivateKey: params.ipnsPrivateKey,
    ipnsPublicKey: params.ipnsPublicKey,
    ipnsName: params.ipnsName,
    sequenceNumber: params.sequenceNumber,
    ctx: params.ctx,
  });

  // 5. Batch publish: file IPNS record + folder IPNS record
  const publishResult = await batchPublishIpnsRecords(
    [{ ...params.fileIpnsRecord, recordType: 'file' as const }, folderResult.record],
    params.ctx
  );

  if (publishResult.totalFailed > 0) {
    throw new Error('Failed to publish one or more IPNS records');
  }

  return { filePointer, newSequenceNumber: folderResult.newSequenceNumber };
}

/**
 * Add multiple files to a folder and batch-publish all IPNS records.
 *
 * Creates FilePointers for each file, builds a single folder IPNS record,
 * and publishes all N file + 1 folder IPNS records in a single batch API call.
 *
 * @returns Created file pointers and new folder sequence number
 * @throws Error if any name collision exists or batch publish fails
 */
export async function addFilesToFolder(params: {
  children: FolderChild[];
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsPublicKey?: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  files: Array<{
    fileId: string;
    name: string;
    fileIpnsRecord: FileIpnsRecordPayload;
    ipnsPrivateKeyEncrypted: string;
  }>;
  ctx: SdkContext;
}): Promise<{ filePointers: FilePointer[]; newSequenceNumber: bigint }> {
  // 1. Build a set of existing child names for collision detection
  const existingNames = new Set(params.children.map((c) => c.name));

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
      ipnsPrivateKeyEncrypted: file.ipnsPrivateKeyEncrypted,
      createdAt: now,
      modifiedAt: now,
    };
    filePointers.push(filePointer);
  }

  // 3. Build updated children array
  const children: FolderChild[] = [...params.children, ...filePointers];

  // 4. Build folder IPNS record
  const folderResult = await buildFolderIpnsRecord({
    children,
    folderKey: params.folderKey,
    ipnsPrivateKey: params.ipnsPrivateKey,
    ipnsPublicKey: params.ipnsPublicKey,
    ipnsName: params.ipnsName,
    sequenceNumber: params.sequenceNumber,
    ctx: params.ctx,
  });

  // 5. Batch publish: all N file IPNS records + 1 folder IPNS record
  const allRecords = [
    ...params.files.map((f) => ({ ...f.fileIpnsRecord, recordType: 'file' as const })),
    folderResult.record,
  ];
  const publishResult = await batchPublishIpnsRecords(allRecords, params.ctx);

  if (publishResult.totalFailed > 0) {
    throw new Error('Failed to publish one or more IPNS records');
  }

  return { filePointers, newSequenceNumber: folderResult.newSequenceNumber };
}

/**
 * Replace file content in v2 metadata (content update).
 *
 * Publishes ONLY the file's IPNS record. The folder metadata is NOT
 * touched because the FilePointer still points to the same fileMetaIpnsName,
 * which now resolves to the updated content.
 *
 * @throws Error if file not found or publish fails
 */
export async function replaceFileInFolder(params: {
  children: FolderChild[];
  fileId: string;
  fileIpnsRecord: FileIpnsRecordPayload;
  ctx: SdkContext;
}): Promise<void> {
  // 1. Verify file exists in parent's children
  const fileExists = params.children.some((c) => c.type === 'file' && c.id === params.fileId);
  if (!fileExists) throw new Error('File not found');

  // 2. Publish ONLY the file IPNS record (folder metadata untouched!)
  const publishResult = await batchPublishIpnsRecords(
    [{ ...params.fileIpnsRecord, recordType: 'file' as const }],
    params.ctx
  );

  if (publishResult.totalFailed > 0) {
    throw new Error('Failed to publish file IPNS record');
  }
}
