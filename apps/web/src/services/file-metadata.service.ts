/**
 * File Metadata Service - Per-file IPNS operations
 *
 * Creates, resolves, and updates per-file IPNS metadata records.
 * Each file gets its own IPNS record containing encrypted metadata,
 * while the parent folder only stores a slim FilePointer reference.
 */

import {
  deriveFileIpnsKeypair,
  encryptFileMetadata,
  decryptFileMetadata,
  createIpnsRecord,
  marshalIpnsRecord,
  wrapKey,
  bytesToHex,
  hexToBytes,
  type FileMetadata,
  type EncryptedFileMetadata,
  type VersionEntry,
} from '@cipherbox/crypto';
import { addToIpfs, fetchFromIpfs } from '../lib/api/ipfs';
import { resolveIpnsRecord } from './ipns.service';
import { useAuthStore } from '../stores/auth.store';

/** IPNS record lifetime: 24 hours in milliseconds */
const IPNS_LIFETIME_MS = 24 * 60 * 60 * 1000;

/** Maximum number of past versions retained per file (VER-04) */
const MAX_VERSIONS_PER_FILE = 10;

/** Cooldown period for automatic version creation (15 minutes in ms) */
const VERSION_COOLDOWN_MS = 15 * 60 * 1000;

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
 * Derives the file's IPNS keypair, encrypts file metadata with the parent
 * folder's key, uploads to IPFS, and creates a signed IPNS record.
 * Returns the record payload ready for batch publish.
 *
 * @param params.fileId - Unique file identifier (UUID)
 * @param params.cid - IPFS CID of the encrypted file content
 * @param params.fileKeyEncrypted - Hex-encoded ECIES-wrapped file key
 * @param params.fileIv - Hex-encoded IV used for file encryption
 * @param params.size - Original file size in bytes
 * @param params.mimeType - MIME type of the original file
 * @param params.folderKey - Parent folder's decrypted AES-256 key
 * @param params.userPrivateKey - User's secp256k1 private key (for HKDF derivation)
 * @param params.encryptionMode - Encryption mode ('GCM' or 'CTR', defaults to 'GCM')
 * @returns File IPNS name and record payload for batch publish
 */
export async function createFileMetadata(params: {
  fileId: string;
  cid: string;
  fileKeyEncrypted: string;
  fileIv: string;
  size: number;
  mimeType: string;
  folderKey: Uint8Array;
  userPrivateKey: Uint8Array;
  encryptionMode?: 'GCM' | 'CTR';
}): Promise<{
  fileMetaIpnsName: string;
  ipnsRecord: FileIpnsRecordPayload;
}> {
  // 1. Derive file IPNS keypair from user private key + fileId
  const ipnsKeypair = await deriveFileIpnsKeypair(params.userPrivateKey, params.fileId);

  // 2. Create FileMetadata object
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

  // 3. Encrypt with parent folderKey
  const encrypted: EncryptedFileMetadata = await encryptFileMetadata(metadata, params.folderKey);

  // 4. Upload encrypted metadata to IPFS
  const blob = new Blob([JSON.stringify(encrypted)], { type: 'application/json' });
  const { cid: metadataCid } = await addToIpfs(blob);

  // 5. Create IPNS record (sequence number 1 for new records)
  const record = await createIpnsRecord(
    ipnsKeypair.privateKey,
    `/ipfs/${metadataCid}`,
    1n,
    IPNS_LIFETIME_MS
  );

  // 6. Marshal and base64 encode the record
  const recordBytes = marshalIpnsRecord(record);
  const recordBase64 = uint8ToBase64(recordBytes);

  // 7. TEE enrollment: encrypt IPNS private key with TEE public key
  let encryptedIpnsPrivateKey: string | undefined;
  let keyEpoch: number | undefined;

  const teeKeys = useAuthStore.getState().teeKeys;
  if (teeKeys?.currentPublicKey) {
    const teePublicKey = hexToBytes(teeKeys.currentPublicKey);
    const encryptedKey = await wrapKey(ipnsKeypair.privateKey, teePublicKey);
    encryptedIpnsPrivateKey = bytesToHex(encryptedKey);
    keyEpoch = teeKeys.currentEpoch;
  }

  return {
    fileMetaIpnsName: ipnsKeypair.ipnsName,
    ipnsRecord: {
      ipnsName: ipnsKeypair.ipnsName,
      recordBase64,
      metadataCid,
      encryptedIpnsPrivateKey,
      keyEpoch,
    },
  };
}

/**
 * Resolve a file's per-IPNS metadata record.
 *
 * Resolves the file's IPNS name to get the current metadata CID,
 * fetches the encrypted metadata from IPFS, and decrypts with the
 * parent folder's key.
 *
 * @param fileMetaIpnsName - IPNS name of the file's metadata record
 * @param folderKey - Parent folder's decrypted AES-256 key
 * @returns Decrypted file metadata and the resolved metadata CID
 * @throws Error if IPNS resolution fails or metadata cannot be decrypted
 */
export async function resolveFileMetadata(
  fileMetaIpnsName: string,
  folderKey: Uint8Array
): Promise<{ metadata: FileMetadata; metadataCid: string }> {
  // 1. Resolve IPNS to get current metadata CID
  const resolved = await resolveIpnsRecord(fileMetaIpnsName);

  if (!resolved) {
    throw new Error('File metadata IPNS not found');
  }

  // 2. Fetch encrypted metadata from IPFS
  const encryptedBytes = await fetchFromIpfs(resolved.cid);

  // 3. Parse and decrypt with parent folder key
  const encryptedJson = new TextDecoder().decode(encryptedBytes);
  const encrypted: EncryptedFileMetadata = JSON.parse(encryptedJson);
  const metadata = await decryptFileMetadata(encrypted, folderKey);

  return { metadata, metadataCid: resolved.cid };
}

/**
 * Determine whether a file content update should create a new version entry.
 *
 * - If `forceVersion` is true, always returns true (web re-upload always versions).
 * - If no versions exist yet, returns true (first version always created).
 * - If the newest version is older than VERSION_COOLDOWN_MS, returns true.
 * - If the newest version is within cooldown, returns false (overwrite without versioning).
 *
 * @param currentMetadata - Current file metadata (may have existing versions)
 * @param forceVersion - Whether to force version creation (e.g., explicit re-upload)
 * @returns true if a new version entry should be created
 */
export function shouldCreateVersion(currentMetadata: FileMetadata, forceVersion: boolean): boolean {
  if (forceVersion) return true;

  const versions = currentMetadata.versions;
  if (!versions || versions.length === 0) return true;

  const newestTimestamp = versions[0].timestamp;
  return Date.now() - newestTimestamp >= VERSION_COOLDOWN_MS;
}

/**
 * Update an existing file's per-IPNS metadata record.
 *
 * Merges updates into the current metadata, re-encrypts, uploads to IPFS,
 * and creates a new IPNS record with an incremented sequence number.
 * Does NOT re-enroll with TEE (already enrolled from creation).
 *
 * @param params.fileId - File identifier (for IPNS keypair derivation)
 * @param params.folderKey - Parent folder's decrypted AES-256 key
 * @param params.userPrivateKey - User's secp256k1 private key (for HKDF derivation)
 * @param params.currentMetadata - Current file metadata to update
 * @param params.updates - Partial updates to apply (cid, fileKeyEncrypted, fileIv, size)
 * @param params.createVersion - Whether to push current metadata into versions array before updating
 * @returns Updated IPNS record payload for publish, plus CIDs of pruned versions to unpin
 */
export async function updateFileMetadata(params: {
  fileId: string;
  folderKey: Uint8Array;
  userPrivateKey: Uint8Array;
  currentMetadata: FileMetadata;
  updates: Partial<Pick<FileMetadata, 'cid' | 'fileKeyEncrypted' | 'fileIv' | 'size'>>;
  createVersion: boolean;
}): Promise<{
  ipnsRecord: FileIpnsRecordPayload;
  prunedCids: string[];
}> {
  // 1. Build version history
  let versions: VersionEntry[] | undefined;
  let prunedCids: string[] = [];

  if (params.createVersion) {
    // Push current state into versions array (newest first)
    const versionEntry: VersionEntry = {
      cid: params.currentMetadata.cid,
      fileKeyEncrypted: params.currentMetadata.fileKeyEncrypted,
      fileIv: params.currentMetadata.fileIv,
      size: params.currentMetadata.size,
      timestamp: Date.now(),
      encryptionMode: params.currentMetadata.encryptionMode ?? 'GCM',
    };
    const allVersions = [versionEntry, ...(params.currentMetadata.versions ?? [])];

    // Prune excess versions beyond limit
    versions = allVersions.slice(0, MAX_VERSIONS_PER_FILE);
    prunedCids = allVersions.slice(MAX_VERSIONS_PER_FILE).map((v) => v.cid);
  } else {
    // Preserve existing versions as-is
    versions = params.currentMetadata.versions;
  }

  // 2. Merge updates into current metadata
  const updatedMetadata: FileMetadata = {
    ...params.currentMetadata,
    ...params.updates,
    // Only include versions field when there are actual versions (backward compat)
    ...(versions && versions.length > 0 ? { versions } : { versions: undefined }),
    modifiedAt: Date.now(),
  };

  // 3. Re-derive file IPNS keypair
  const ipnsKeypair = await deriveFileIpnsKeypair(params.userPrivateKey, params.fileId);

  // 4. Resolve current IPNS to get sequence number
  const resolved = await resolveIpnsRecord(ipnsKeypair.ipnsName);
  if (!resolved) {
    throw new Error(
      `Cannot update file metadata: existing IPNS record not found for ${ipnsKeypair.ipnsName}`
    );
  }
  const currentSeq = resolved.sequenceNumber;
  const newSeq = currentSeq + 1n;

  // 5. Encrypt updated metadata with folderKey
  const encrypted = await encryptFileMetadata(updatedMetadata, params.folderKey);

  // 6. Upload to IPFS
  const blob = new Blob([JSON.stringify(encrypted)], { type: 'application/json' });
  const { cid: metadataCid } = await addToIpfs(blob);

  // 7. Create new IPNS record with incremented sequence number
  const record = await createIpnsRecord(
    ipnsKeypair.privateKey,
    `/ipfs/${metadataCid}`,
    newSeq,
    IPNS_LIFETIME_MS
  );

  const recordBytes = marshalIpnsRecord(record);
  const recordBase64 = uint8ToBase64(recordBytes);

  return {
    ipnsRecord: {
      ipnsName: ipnsKeypair.ipnsName,
      recordBase64,
      metadataCid,
    },
    prunedCids,
  };
}

/**
 * Restore a previous version of a file.
 * The current content becomes a new version entry, and the restored version's
 * data becomes the current content. Non-destructive: version chain grows.
 *
 * @param params.fileId - File identifier (for IPNS keypair derivation)
 * @param params.folderKey - Parent folder's decrypted AES-256 key
 * @param params.userPrivateKey - User's secp256k1 private key
 * @param params.currentMetadata - Current file metadata
 * @param params.versionIndex - Index of version to restore (0 = newest past version)
 * @returns Updated IPNS record payload and any pruned CIDs
 */
export async function restoreVersion(params: {
  fileId: string;
  folderKey: Uint8Array;
  userPrivateKey: Uint8Array;
  currentMetadata: FileMetadata;
  versionIndex: number;
}): Promise<{ ipnsRecord: FileIpnsRecordPayload; prunedCids: string[] }> {
  const versions = params.currentMetadata.versions;
  if (!versions || params.versionIndex < 0 || params.versionIndex >= versions.length) {
    throw new Error('Invalid version index');
  }

  const versionToRestore = versions[params.versionIndex];

  // Build a version entry from CURRENT metadata (it becomes a past version)
  const currentAsVersion: VersionEntry = {
    cid: params.currentMetadata.cid,
    fileKeyEncrypted: params.currentMetadata.fileKeyEncrypted,
    fileIv: params.currentMetadata.fileIv,
    size: params.currentMetadata.size,
    timestamp: Date.now(),
    encryptionMode: params.currentMetadata.encryptionMode ?? 'GCM',
  };

  // Remove restored version from array, prepend current as new version entry
  const remainingVersions = versions.filter((_, i) => i !== params.versionIndex);
  const newVersions = [currentAsVersion, ...remainingVersions];

  // Prune if exceeds max
  const prunedVersions = newVersions.slice(0, MAX_VERSIONS_PER_FILE);
  const prunedCids = newVersions.slice(MAX_VERSIONS_PER_FILE).map((v) => v.cid);

  // Build updated metadata with restored version's data as current
  const updatedMetadata: FileMetadata = {
    ...params.currentMetadata,
    cid: versionToRestore.cid,
    fileKeyEncrypted: versionToRestore.fileKeyEncrypted,
    fileIv: versionToRestore.fileIv,
    size: versionToRestore.size,
    encryptionMode: versionToRestore.encryptionMode,
    versions: prunedVersions.length > 0 ? prunedVersions : undefined,
    modifiedAt: Date.now(),
  };

  // Re-derive IPNS keypair
  const ipnsKeypair = await deriveFileIpnsKeypair(params.userPrivateKey, params.fileId);

  // Resolve current IPNS to get sequence number
  const resolved = await resolveIpnsRecord(ipnsKeypair.ipnsName);
  if (!resolved) {
    throw new Error(
      `Cannot restore version: existing IPNS record not found for ${ipnsKeypair.ipnsName}`
    );
  }
  const newSeq = resolved.sequenceNumber + 1n;

  // Encrypt updated metadata with folderKey
  const encrypted = await encryptFileMetadata(updatedMetadata, params.folderKey);

  // Upload to IPFS
  const blob = new Blob([JSON.stringify(encrypted)], { type: 'application/json' });
  const { cid: metadataCid } = await addToIpfs(blob);

  // Create new IPNS record with incremented sequence number
  const record = await createIpnsRecord(
    ipnsKeypair.privateKey,
    `/ipfs/${metadataCid}`,
    newSeq,
    IPNS_LIFETIME_MS
  );

  const recordBytes = marshalIpnsRecord(record);
  const recordBase64 = uint8ToBase64(recordBytes);

  return {
    ipnsRecord: {
      ipnsName: ipnsKeypair.ipnsName,
      recordBase64,
      metadataCid,
    },
    prunedCids,
  };
}

/**
 * Delete a specific past version from a file's version history.
 * Updates the file's IPNS metadata without the deleted version.
 *
 * @param params.fileId - File identifier
 * @param params.folderKey - Parent folder's decrypted AES-256 key
 * @param params.userPrivateKey - User's secp256k1 private key
 * @param params.currentMetadata - Current file metadata
 * @param params.versionIndex - Index of version to delete
 * @returns Updated IPNS record and CID to unpin
 */
export async function deleteVersion(params: {
  fileId: string;
  folderKey: Uint8Array;
  userPrivateKey: Uint8Array;
  currentMetadata: FileMetadata;
  versionIndex: number;
}): Promise<{ ipnsRecord: FileIpnsRecordPayload; deletedCid: string }> {
  const versions = params.currentMetadata.versions;
  if (!versions || params.versionIndex < 0 || params.versionIndex >= versions.length) {
    throw new Error('Invalid version index');
  }

  const deletedCid = versions[params.versionIndex].cid;
  const newVersions = versions.filter((_, i) => i !== params.versionIndex);

  // Build updated metadata with filtered versions
  const updatedMetadata: FileMetadata = {
    ...params.currentMetadata,
    versions: newVersions.length > 0 ? newVersions : undefined,
  };

  // Re-derive IPNS keypair
  const ipnsKeypair = await deriveFileIpnsKeypair(params.userPrivateKey, params.fileId);

  // Resolve current IPNS to get sequence number
  const resolved = await resolveIpnsRecord(ipnsKeypair.ipnsName);
  if (!resolved) {
    throw new Error(
      `Cannot delete version: existing IPNS record not found for ${ipnsKeypair.ipnsName}`
    );
  }
  const newSeq = resolved.sequenceNumber + 1n;

  // Encrypt updated metadata with folderKey
  const encrypted = await encryptFileMetadata(updatedMetadata, params.folderKey);

  // Upload to IPFS
  const blob = new Blob([JSON.stringify(encrypted)], { type: 'application/json' });
  const { cid: metadataCid } = await addToIpfs(blob);

  // Create new IPNS record with incremented sequence number
  const record = await createIpnsRecord(
    ipnsKeypair.privateKey,
    `/ipfs/${metadataCid}`,
    newSeq,
    IPNS_LIFETIME_MS
  );

  const recordBytes = marshalIpnsRecord(record);
  const recordBase64 = uint8ToBase64(recordBytes);

  return {
    ipnsRecord: {
      ipnsName: ipnsKeypair.ipnsName,
      recordBase64,
      metadataCid,
    },
    deletedCid,
  };
}
