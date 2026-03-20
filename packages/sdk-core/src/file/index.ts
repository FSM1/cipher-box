/**
 * File Metadata Service - Per-file IPNS operations
 *
 * Extracted from: apps/web/src/services/file-metadata.service.ts
 * Change: teeKeys passed explicitly instead of read from useAuthStore.
 * Change: IPFS/IPNS operations use sdk-core internal modules instead of web app imports.
 */

import {
  generateFileIpnsKeypair,
  encryptFileMetadata,
  decryptFileMetadata,
  createIpnsRecord,
  marshalIpnsRecord,
  type FileMetadata,
  type EncryptedFileMetadata,
  type VersionEntry,
} from '@cipherbox/core';
import { wrapKey, bytesToHex, hexToBytes } from '@cipherbox/crypto';
import type { SdkContext, TeeKeys } from '../types';
import { addToIpfs, fetchFromIpfs } from '../ipfs';
import { resolveIpnsRecord } from '../ipns';

/** IPNS record lifetime: 24 hours in milliseconds */
const IPNS_LIFETIME_MS = 24 * 60 * 60 * 1000;

/** Maximum number of past versions retained per file (VER-04) */
const MAX_VERSIONS_PER_FILE = 10;

/** Safe base64 encoding that avoids call stack overflow from spread operator */
function uint8ToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/** Record payload ready for batch publish */
export type FileIpnsRecordPayload = {
  ipnsName: string;
  recordBase64: string;
  metadataCid: string;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
};

/**
 * Create a per-file IPNS metadata record.
 *
 * Generates a random Ed25519 IPNS keypair for the file, encrypts file metadata
 * with the parent folder's key, uploads to IPFS, and creates a signed IPNS record.
 *
 * @returns File IPNS name, record payload for batch publish, and ECIES-wrapped IPNS private key
 */
export async function createFileMetadata(params: {
  fileId: string;
  cid: string;
  fileKeyEncrypted: string;
  fileIv: string;
  size: number;
  mimeType: string;
  folderKey: Uint8Array;
  userPublicKey: Uint8Array;
  ctx: SdkContext;
  teeKeys?: TeeKeys;
  encryptionMode?: 'GCM' | 'CTR';
}): Promise<{
  fileMetaIpnsName: string;
  ipnsRecord: FileIpnsRecordPayload;
  ipnsPrivateKeyEncrypted: string;
}> {
  // 1. Generate random Ed25519 IPNS keypair for this file
  const ipnsKeypair = await generateFileIpnsKeypair();

  // 2. ECIES-wrap the IPNS private key with user's public key for storage in FilePointer
  const wrappedIpnsKey = await wrapKey(ipnsKeypair.privateKey, params.userPublicKey);
  const ipnsPrivateKeyEncrypted = bytesToHex(wrappedIpnsKey);

  // 3. Create FileMetadata object, upload, sign, and TEE-enroll.
  //    Wrap in try/catch to zero IPNS private key on error paths.
  //    On success the caller receives the key (via ipnsPrivateKeyEncrypted),
  //    so we only zero on failure.
  try {
    const now = Date.now();
    const metadata: FileMetadata = {
      version: 'v1',
      cid: params.cid,
      fileKeyEncrypted: params.fileKeyEncrypted,
      fileIv: params.fileIv,
      size: params.size,
      mimeType: params.mimeType,
      encryptionMode: params.encryptionMode ?? 'GCM',
      createdAt: now,
      modifiedAt: now,
    };

    // 4. Encrypt with parent folderKey
    const encrypted: EncryptedFileMetadata = await encryptFileMetadata(metadata, params.folderKey);

    // 5. Upload encrypted metadata to IPFS
    const jsonStr = JSON.stringify(encrypted);
    const encryptedBytes = new TextEncoder().encode(jsonStr);
    const { cid: metadataCid } = await addToIpfs(params.ctx, encryptedBytes);

    // 6. Create IPNS record (sequence number 1 for new records)
    const record = await createIpnsRecord(
      ipnsKeypair.privateKey,
      `/ipfs/${metadataCid}`,
      1n,
      IPNS_LIFETIME_MS
    );

    // 7. Marshal and base64 encode the record
    const recordBytes = marshalIpnsRecord(record);
    const recordBase64 = uint8ToBase64(recordBytes);

    // 8. TEE enrollment: encrypt IPNS private key with TEE public key
    let teeEncryptedIpnsPrivateKey: string | undefined;
    let keyEpoch: number | undefined;

    if (params.teeKeys?.currentPublicKey) {
      const teePublicKey = hexToBytes(params.teeKeys.currentPublicKey);
      const encryptedKey = await wrapKey(ipnsKeypair.privateKey, teePublicKey);
      teeEncryptedIpnsPrivateKey = bytesToHex(encryptedKey);
      keyEpoch = params.teeKeys.currentEpoch;
    }

    // Zero the private key now that wrapping, signing, and TEE enrollment are done
    ipnsKeypair.privateKey.fill(0);

    return {
      fileMetaIpnsName: ipnsKeypair.ipnsName,
      ipnsRecord: {
        ipnsName: ipnsKeypair.ipnsName,
        recordBase64,
        metadataCid,
        encryptedIpnsPrivateKey: teeEncryptedIpnsPrivateKey,
        keyEpoch,
      },
      ipnsPrivateKeyEncrypted,
    };
  } catch (error) {
    ipnsKeypair.privateKey.fill(0);
    throw error;
  }
}

/**
 * Resolve a file's per-IPNS metadata record.
 *
 * Resolves the file's IPNS name to get the current metadata CID,
 * fetches the encrypted metadata from IPFS, and decrypts with the
 * parent folder's key.
 *
 * @returns Decrypted file metadata and the resolved metadata CID
 */
export async function resolveFileMetadata(
  fileMetaIpnsName: string,
  folderKey: Uint8Array,
  ctx: SdkContext
): Promise<{ metadata: FileMetadata; metadataCid: string }> {
  const resolved = await resolveIpnsRecord(fileMetaIpnsName);

  if (!resolved) {
    throw new Error('File metadata IPNS not found');
  }

  const encryptedBytes = await fetchFromIpfs(ctx, resolved.cid);
  const encryptedJson = new TextDecoder().decode(encryptedBytes);
  const encrypted: EncryptedFileMetadata = JSON.parse(encryptedJson);
  const metadata = await decryptFileMetadata(encrypted, folderKey);

  return { metadata, metadataCid: resolved.cid };
}

/**
 * Update an existing file's per-IPNS metadata record.
 *
 * Merges updates into the current metadata, re-encrypts, uploads to IPFS,
 * and creates a new IPNS record with an incremented sequence number.
 *
 * @returns Updated IPNS record payload for publish, plus CIDs of pruned versions to unpin
 */
export async function updateFileMetadata(params: {
  fileIpnsPrivateKey: Uint8Array;
  fileMetaIpnsName: string;
  folderKey: Uint8Array;
  currentMetadata: FileMetadata;
  updates: Partial<
    Pick<FileMetadata, 'cid' | 'fileKeyEncrypted' | 'fileIv' | 'size' | 'encryptionMode'>
  >;
  createVersion: boolean;
  ctx: SdkContext;
}): Promise<{
  ipnsRecord: FileIpnsRecordPayload;
  prunedCids: string[];
}> {
  // 1. Build version history
  let versions: VersionEntry[] | undefined;
  let prunedCids: string[] = [];

  if (params.createVersion) {
    const versionEntry: VersionEntry = {
      cid: params.currentMetadata.cid,
      fileKeyEncrypted: params.currentMetadata.fileKeyEncrypted,
      fileIv: params.currentMetadata.fileIv,
      size: params.currentMetadata.size,
      timestamp: Date.now(),
      encryptionMode: params.currentMetadata.encryptionMode ?? 'GCM',
    };
    const allVersions = [versionEntry, ...(params.currentMetadata.versions ?? [])];

    versions = allVersions.slice(0, MAX_VERSIONS_PER_FILE);
    prunedCids = allVersions.slice(MAX_VERSIONS_PER_FILE).map((v) => v.cid);
  } else {
    versions = params.currentMetadata.versions;
  }

  // 2. Merge updates into current metadata
  const updatedMetadata: FileMetadata = {
    ...params.currentMetadata,
    ...params.updates,
    ...(versions && versions.length > 0 ? { versions } : { versions: undefined }),
    modifiedAt: Date.now(),
  };

  // 3. Resolve current IPNS to get sequence number
  const resolved = await resolveIpnsRecord(params.fileMetaIpnsName);
  if (!resolved) {
    throw new Error(
      `Cannot update file metadata: existing IPNS record not found for ${params.fileMetaIpnsName}`
    );
  }
  const newSeq = resolved.sequenceNumber + 1n;

  // 4. Encrypt updated metadata with folderKey
  const encrypted = await encryptFileMetadata(updatedMetadata, params.folderKey);

  // 5. Upload to IPFS
  const jsonStr = JSON.stringify(encrypted);
  const encryptedBytes = new TextEncoder().encode(jsonStr);
  const { cid: metadataCid } = await addToIpfs(params.ctx, encryptedBytes);

  // 6. Create new IPNS record with incremented sequence number
  const record = await createIpnsRecord(
    params.fileIpnsPrivateKey,
    `/ipfs/${metadataCid}`,
    newSeq,
    IPNS_LIFETIME_MS
  );

  const recordBytes = marshalIpnsRecord(record);
  const recordBase64 = uint8ToBase64(recordBytes);

  return {
    ipnsRecord: {
      ipnsName: params.fileMetaIpnsName,
      recordBase64,
      metadataCid,
    },
    prunedCids,
  };
}
