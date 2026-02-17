/**
 * @cipherbox/crypto - File Metadata Encryption
 *
 * Encrypts and decrypts per-file metadata using AES-256-GCM.
 * File metadata is encrypted with the parent folder's folderKey
 * (NOT the file's own encryption key).
 */

import { encryptAesGcm, decryptAesGcm } from '../aes';
import { generateIv, bytesToHex, hexToBytes } from '../utils';
import { CryptoError } from '../types';
import type { FileMetadata, EncryptedFileMetadata } from './types';

/**
 * [SECURITY: MEDIUM-08] Chunk-based base64 encoding to avoid call stack issues
 * with large Uint8Arrays (spread operator has argument limits ~65536)
 */
function uint8ArrayToBase64(bytes: Uint8Array): string {
  const CHUNK_SIZE = 32768;
  let result = '';
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.length));
    result += String.fromCharCode(...chunk);
  }
  return btoa(result);
}

/**
 * [SECURITY: MEDIUM-07] Runtime validation for decrypted file metadata.
 * Ensures the decrypted data conforms to the expected FileMetadata schema.
 */
export function validateFileMetadata(data: unknown): FileMetadata {
  if (typeof data !== 'object' || data === null) {
    throw new CryptoError('Invalid file metadata format: not an object', 'DECRYPTION_FAILED');
  }

  const obj = data as Record<string, unknown>;

  // Validate version field
  if (obj.version !== 'v1') {
    throw new CryptoError('Invalid file metadata format: unsupported version', 'DECRYPTION_FAILED');
  }

  // Validate required string fields
  if (typeof obj.cid !== 'string') {
    throw new CryptoError('Invalid file metadata format: cid must be string', 'DECRYPTION_FAILED');
  }
  if (typeof obj.fileKeyEncrypted !== 'string') {
    throw new CryptoError(
      'Invalid file metadata format: fileKeyEncrypted must be string',
      'DECRYPTION_FAILED'
    );
  }
  if (typeof obj.fileIv !== 'string') {
    throw new CryptoError(
      'Invalid file metadata format: fileIv must be string',
      'DECRYPTION_FAILED'
    );
  }
  if (typeof obj.mimeType !== 'string') {
    throw new CryptoError(
      'Invalid file metadata format: mimeType must be string',
      'DECRYPTION_FAILED'
    );
  }

  // Validate required number fields
  if (typeof obj.size !== 'number') {
    throw new CryptoError('Invalid file metadata format: size must be number', 'DECRYPTION_FAILED');
  }
  if (typeof obj.createdAt !== 'number') {
    throw new CryptoError(
      'Invalid file metadata format: createdAt must be number',
      'DECRYPTION_FAILED'
    );
  }
  if (typeof obj.modifiedAt !== 'number') {
    throw new CryptoError(
      'Invalid file metadata format: modifiedAt must be number',
      'DECRYPTION_FAILED'
    );
  }

  // Validate optional encryptionMode: if present must be 'GCM' or 'CTR'; if absent default to 'GCM'
  if (obj.encryptionMode !== undefined) {
    if (obj.encryptionMode !== 'GCM' && obj.encryptionMode !== 'CTR') {
      throw new CryptoError(
        'Invalid file metadata format: encryptionMode must be GCM or CTR',
        'DECRYPTION_FAILED'
      );
    }
  }

  return {
    version: 'v1',
    cid: obj.cid as string,
    fileKeyEncrypted: obj.fileKeyEncrypted as string,
    fileIv: obj.fileIv as string,
    size: obj.size as number,
    mimeType: obj.mimeType as string,
    encryptionMode: (obj.encryptionMode as 'GCM' | 'CTR' | undefined) ?? 'GCM',
    createdAt: obj.createdAt as number,
    modifiedAt: obj.modifiedAt as number,
  };
}

/**
 * Encrypts file metadata with AES-256-GCM using the parent folder's key.
 *
 * @param metadata - Plaintext file metadata object
 * @param folderKey - 32-byte AES key of the parent folder
 * @returns Encrypted metadata with IV (hex) and ciphertext (base64)
 */
export async function encryptFileMetadata(
  metadata: FileMetadata,
  folderKey: Uint8Array
): Promise<EncryptedFileMetadata> {
  // Generate random IV for this encryption
  const iv = generateIv();

  // Serialize metadata to JSON bytes
  const plaintext = new TextEncoder().encode(JSON.stringify(metadata));

  // Encrypt with AES-256-GCM
  const ciphertext = await encryptAesGcm(plaintext, folderKey, iv);

  // Encode for storage
  // [SECURITY: MEDIUM-08] Use chunked base64 encoding for large metadata
  return {
    iv: bytesToHex(iv),
    data: uint8ArrayToBase64(ciphertext),
  };
}

/**
 * Decrypts file metadata encrypted with AES-256-GCM.
 *
 * @param encrypted - Encrypted metadata with IV (hex) and ciphertext (base64)
 * @param folderKey - 32-byte AES key of the parent folder
 * @returns Decrypted file metadata object
 * @throws CryptoError if decryption fails (wrong key, corrupted data, etc.)
 */
export async function decryptFileMetadata(
  encrypted: EncryptedFileMetadata,
  folderKey: Uint8Array
): Promise<FileMetadata> {
  // Decode IV and ciphertext
  const iv = hexToBytes(encrypted.iv);
  const ciphertext = Uint8Array.from(atob(encrypted.data), (c) => c.charCodeAt(0));

  // Decrypt with AES-256-GCM
  const plaintext = await decryptAesGcm(ciphertext, folderKey, iv);

  // Parse JSON back to metadata object
  // [SECURITY: MEDIUM-07] Validate the decrypted data before returning
  const parsed = JSON.parse(new TextDecoder().decode(plaintext));
  return validateFileMetadata(parsed);
}
