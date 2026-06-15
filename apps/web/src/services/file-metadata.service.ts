/**
 * File Metadata Service - Per-file IPNS operations
 *
 * Creates, resolves, and updates per-file IPNS metadata records.
 * Each file gets its own IPNS record containing encrypted metadata,
 * while the parent folder only stores a slim FilePointer reference.
 */

import {
  deriveFileIpnsKeypair,
  generateFileIpnsKeypair,
  encryptFileMetadata,
  decryptFileMetadata,
  createIpnsRecord,
  marshalIpnsRecord,
  type FileMetadata,
  type FilePointer,
  type EncryptedFileMetadata,
  type VersionEntry,
} from '@cipherbox/core';
import { wrapKey, unwrapKey, bytesToHex, hexToBytes } from '@cipherbox/crypto';
import { addToIpfs, fetchFromIpfs } from '../lib/api/ipfs';
import { resolveIpnsRecord } from './ipns.service';
import { useAuthStore } from '../stores/auth.store';
import { useVaultSettingsStore } from '../stores/vault-settings.store';

/** IPNS record lifetime: 24 hours in milliseconds */
const IPNS_LIFETIME_MS = 24 * 60 * 60 * 1000;

/** Read max versions from user settings (falls back to default 10 if store not loaded) */
function getMaxVersionsPerFile(): number {
  return useVaultSettingsStore.getState().settings.maxVersionsPerFile;
}

/** Read version cooldown from user settings, converted to milliseconds */
function getVersionCooldownMs(): number {
  return useVaultSettingsStore.getState().settings.versionCooldownMinutes * 60 * 1000;
}

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
 * Retrieve the IPNS private key for a file, decrypting from the FilePointer
 * if available, or falling back to HKDF derivation for legacy files.
 *
 * When HKDF fallback is used and userPublicKey is provided, the derived key
 * is ECIES-wrapped for lazy migration: the caller should persist the wrapped
 * key in the FilePointer and re-publish folder metadata.
 *
 * @param filePointer - FilePointer containing optional encrypted IPNS key
 * @param userPrivateKey - User's secp256k1 private key (for ECIES unwrap or HKDF fallback)
 * @param userPublicKey - User's secp256k1 public key (for wrapping during lazy migration)
 * @returns Decrypted Ed25519 IPNS private key, plus migration data if HKDF fallback was used
 * @remarks The caller is responsible for zeroing `privateKey` with `.fill(0)` after use.
 */
export async function getFileIpnsPrivateKey(
  filePointer: FilePointer,
  userPrivateKey: Uint8Array,
  userPublicKey?: Uint8Array
): Promise<{ privateKey: Uint8Array; migratedIpnsPrivateKeyEncrypted?: string }> {
  if (filePointer.ipnsPrivateKeyEncrypted) {
    const privateKey = await unwrapKey(
      hexToBytes(filePointer.ipnsPrivateKeyEncrypted),
      userPrivateKey
    );
    return { privateKey };
  }
  // Fallback: HKDF derivation for legacy FilePointers without encrypted key
  const derived = await deriveFileIpnsKeypair(userPrivateKey, filePointer.id);

  // Wrap derived key for lazy migration if public key is available
  let migratedIpnsPrivateKeyEncrypted: string | undefined;
  if (userPublicKey) {
    const wrapped = await wrapKey(derived.privateKey, userPublicKey);
    migratedIpnsPrivateKeyEncrypted = bytesToHex(wrapped);
  }

  return { privateKey: derived.privateKey, migratedIpnsPrivateKeyEncrypted };
}

/**
 * Create a per-file IPNS metadata record.
 *
 * Generates a random Ed25519 IPNS keypair for the file, encrypts file metadata
 * with the parent folder's key, uploads to IPFS, and creates a signed IPNS record.
 * Returns the record payload ready for batch publish, plus the ECIES-wrapped
 * IPNS private key for storage in the FilePointer.
 *
 * @param params.fileId - Unique file identifier (UUID)
 * @param params.cid - IPFS CID of the encrypted file content
 * @param params.fileKeyEncrypted - Hex-encoded ECIES-wrapped file key
 * @param params.fileIv - Hex-encoded IV used for file encryption
 * @param params.size - Original file size in bytes
 * @param params.mimeType - MIME type of the original file
 * @param params.folderKey - Parent folder's decrypted AES-256 key
 * @param params.userPublicKey - User's secp256k1 public key (for ECIES wrapping)
 * @param params.encryptionMode - Encryption mode ('GCM' or 'CTR', defaults to 'GCM')
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

  // 3. Create FileMetadata object
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
  const blob = new Blob([JSON.stringify(encrypted)], { type: 'application/json' });
  const { cid: metadataCid } = await addToIpfs(blob);

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

  const teeKeys = useAuthStore.getState().teeKeys;
  if (teeKeys?.currentPublicKey) {
    const teePublicKey = hexToBytes(teeKeys.currentPublicKey);
    const encryptedKey = await wrapKey(ipnsKeypair.privateKey, teePublicKey);
    teeEncryptedIpnsPrivateKey = bytesToHex(encryptedKey);
    keyEpoch = teeKeys.currentEpoch;
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
 * - If the newest version is older than the configurable cooldown, returns true.
 * - If the newest version is within cooldown, returns false (overwrite without versioning).
 *
 * Cooldown is configurable via vault settings and obtained through getVersionCooldownMs().
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
  return Date.now() - newestTimestamp >= getVersionCooldownMs();
}

/**
 * Update an existing file's per-IPNS metadata record.
 *
 * Merges updates into the current metadata, re-encrypts, uploads to IPFS,
 * and creates a new IPNS record with an incremented sequence number.
 * Does NOT re-enroll with TEE (already enrolled from creation).
 *
 * @param params.fileIpnsPrivateKey - Decrypted Ed25519 IPNS private key for this file
 * @param params.fileMetaIpnsName - IPNS name for this file's metadata record
 * @param params.folderKey - Parent folder's decrypted AES-256 key
 * @param params.currentMetadata - Current file metadata to update
 * @param params.updates - Partial updates to apply (cid, fileKeyEncrypted, fileIv, size)
 * @param params.createVersion - Whether to push current metadata into versions array before updating
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
    const maxVersions = getMaxVersionsPerFile();
    versions = allVersions.slice(0, maxVersions);
    prunedCids = allVersions.slice(maxVersions).map((v) => v.cid);
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

  // 3. Resolve current IPNS to get sequence number
  const resolved = await resolveIpnsRecord(params.fileMetaIpnsName);
  if (!resolved) {
    throw new Error(
      `Cannot update file metadata: existing IPNS record not found for ${params.fileMetaIpnsName}`
    );
  }
  const currentSeq = resolved.sequenceNumber;
  const newSeq = currentSeq + 1n;

  // 4. Encrypt updated metadata with folderKey
  const encrypted = await encryptFileMetadata(updatedMetadata, params.folderKey);

  // 5. Upload to IPFS
  const blob = new Blob([JSON.stringify(encrypted)], { type: 'application/json' });
  const { cid: metadataCid } = await addToIpfs(blob);

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

/** Content fields applied as `updates` when routing a file metadata write through the SDK client. */
export type FileContentUpdates = Partial<
  Pick<FileMetadata, 'cid' | 'fileKeyEncrypted' | 'fileIv' | 'size' | 'encryptionMode'>
>;

/**
 * Compute the metadata transform for restoring a previous version (pure, no publish).
 *
 * The current content becomes a new version entry, the restored version's data
 * becomes the current content, the restored version is removed from history, and
 * the history is capped at the configured maximum.
 *
 * The result is shaped for the SDK client's `restoreFileVersion` contract:
 *   - `currentMetadata`: the original metadata with its `versions` array already
 *     transformed to the post-restore retained set (the client passes this through
 *     `sdkCore.updateFileMetadata` with `createVersion: false`, which preserves
 *     these versions and applies `updates` as the new current content).
 *   - `updates`: the restored content fields to set as the new current content.
 *   - `prunedCids`: version CIDs evicted beyond the cap, for the caller to unpin.
 *
 * @param currentMetadata - Current file metadata (must contain `versions`)
 * @param versionIndex - Index of version to restore (0 = newest past version)
 * @returns Transformed currentMetadata, content updates, and pruned CIDs
 */
export function computeRestoreVersionUpdate(
  currentMetadata: FileMetadata,
  versionIndex: number
): { currentMetadata: FileMetadata; updates: FileContentUpdates; prunedCids: string[] } {
  const versions = currentMetadata.versions;
  if (!versions || versionIndex < 0 || versionIndex >= versions.length) {
    throw new Error('Invalid version index');
  }

  const versionToRestore = versions[versionIndex];

  // Build a version entry from CURRENT metadata (it becomes a past version)
  const currentAsVersion: VersionEntry = {
    cid: currentMetadata.cid,
    fileKeyEncrypted: currentMetadata.fileKeyEncrypted,
    fileIv: currentMetadata.fileIv,
    size: currentMetadata.size,
    timestamp: Date.now(),
    encryptionMode: currentMetadata.encryptionMode ?? 'GCM',
  };

  // Remove restored version from array, prepend current as new version entry
  const remainingVersions = versions.filter((_, i) => i !== versionIndex);
  const newVersions = [currentAsVersion, ...remainingVersions];

  // Prune if exceeds max
  const maxVer = getMaxVersionsPerFile();
  const retainedVersions = newVersions.slice(0, maxVer);
  const prunedCids = newVersions.slice(maxVer).map((v) => v.cid);

  // currentMetadata carries the transformed versions; the client's updateFileMetadata
  // (createVersion: false) preserves these and overwrites the content fields via updates.
  return {
    currentMetadata: {
      ...currentMetadata,
      versions: retainedVersions.length > 0 ? retainedVersions : undefined,
    },
    updates: {
      cid: versionToRestore.cid,
      fileKeyEncrypted: versionToRestore.fileKeyEncrypted,
      fileIv: versionToRestore.fileIv,
      size: versionToRestore.size,
      encryptionMode: versionToRestore.encryptionMode,
    },
    prunedCids,
  };
}

/**
 * Compute the metadata transform for deleting a past version (pure, no publish).
 *
 * Removes the version at `versionIndex` from the history. The current content is
 * untouched (no `updates`), so the client publishes the same content with a pruned
 * version list.
 *
 * @param currentMetadata - Current file metadata (must contain `versions`)
 * @param versionIndex - Index of version to delete
 * @returns Transformed currentMetadata, empty content updates, and the deleted CID
 */
export function computeDeleteVersionUpdate(
  currentMetadata: FileMetadata,
  versionIndex: number
): { currentMetadata: FileMetadata; updates: FileContentUpdates; deletedCid: string } {
  const versions = currentMetadata.versions;
  if (!versions || versionIndex < 0 || versionIndex >= versions.length) {
    throw new Error('Invalid version index');
  }

  const deletedCid = versions[versionIndex].cid;
  const newVersions = versions.filter((_, i) => i !== versionIndex);

  return {
    currentMetadata: {
      ...currentMetadata,
      versions: newVersions.length > 0 ? newVersions : undefined,
    },
    updates: {},
    deletedCid,
  };
}
