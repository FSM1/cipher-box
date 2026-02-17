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
} from '@cipherbox/crypto';
import { addToIpfs, fetchFromIpfs } from '../lib/api/ipfs';
import { resolveIpnsRecord } from './ipns.service';
import { useAuthStore } from '../stores/auth.store';

/** IPNS record lifetime: 24 hours in milliseconds */
const IPNS_LIFETIME_MS = 24 * 60 * 60 * 1000;

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
 * @returns Decrypted file metadata
 * @throws Error if IPNS resolution fails or metadata cannot be decrypted
 */
export async function resolveFileMetadata(
  fileMetaIpnsName: string,
  folderKey: Uint8Array
): Promise<FileMetadata> {
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

  return metadata;
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
 * @returns Updated IPNS record payload for publish
 */
export async function updateFileMetadata(params: {
  fileId: string;
  folderKey: Uint8Array;
  userPrivateKey: Uint8Array;
  currentMetadata: FileMetadata;
  updates: Partial<Pick<FileMetadata, 'cid' | 'fileKeyEncrypted' | 'fileIv' | 'size'>>;
}): Promise<{
  ipnsRecord: FileIpnsRecordPayload;
}> {
  // 1. Merge updates into current metadata
  const updatedMetadata: FileMetadata = {
    ...params.currentMetadata,
    ...params.updates,
    modifiedAt: Date.now(),
  };

  // 2. Re-derive file IPNS keypair
  const ipnsKeypair = await deriveFileIpnsKeypair(params.userPrivateKey, params.fileId);

  // 3. Resolve current IPNS to get sequence number
  const resolved = await resolveIpnsRecord(ipnsKeypair.ipnsName);
  if (!resolved) {
    throw new Error(
      `Cannot update file metadata: existing IPNS record not found for ${ipnsKeypair.ipnsName}`
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
  };
}
