/**
 * @cipherbox/crypto - Folder Metadata Encryption
 *
 * Encrypts and decrypts folder metadata using AES-256-GCM.
 * Folder metadata is JSON serialized before encryption.
 */

import { encryptAesGcm, decryptAesGcm } from '../aes';
import { generateIv, bytesToHex, hexToBytes } from '../utils';
import { CryptoError } from '../types';
import type { FolderMetadata, EncryptedFolderMetadata } from './types';

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
 * [SECURITY: MEDIUM-07] Runtime validation for decrypted folder metadata
 * Ensures the decrypted data conforms to the expected FolderMetadata schema
 */
function validateFolderMetadata(data: unknown): FolderMetadata {
  if (typeof data !== 'object' || data === null) {
    throw new CryptoError('Invalid metadata format: not an object', 'DECRYPTION_FAILED');
  }

  const obj = data as Record<string, unknown>;

  // Validate version field
  if (obj.version !== 'v1') {
    throw new CryptoError('Invalid metadata format: unsupported version', 'DECRYPTION_FAILED');
  }

  // Validate children array
  if (!Array.isArray(obj.children)) {
    throw new CryptoError('Invalid metadata format: children must be array', 'DECRYPTION_FAILED');
  }

  // Basic validation of each child entry
  for (const child of obj.children) {
    if (typeof child !== 'object' || child === null) {
      throw new CryptoError('Invalid metadata format: invalid child entry', 'DECRYPTION_FAILED');
    }
    const entry = child as Record<string, unknown>;
    if (entry.type !== 'file' && entry.type !== 'folder') {
      throw new CryptoError('Invalid metadata format: unknown child type', 'DECRYPTION_FAILED');
    }
    if (typeof entry.id !== 'string' || typeof entry.name !== 'string') {
      throw new CryptoError('Invalid metadata format: missing id or name', 'DECRYPTION_FAILED');
    }
  }

  return data as FolderMetadata;
}

/**
 * Encrypts folder metadata with AES-256-GCM.
 *
 * @param metadata - Plaintext folder metadata object
 * @param folderKey - 32-byte AES key for this folder
 * @returns Encrypted metadata with IV (hex) and ciphertext (base64)
 */
export async function encryptFolderMetadata(
  metadata: FolderMetadata,
  folderKey: Uint8Array
): Promise<EncryptedFolderMetadata> {
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
 * Decrypts folder metadata encrypted with AES-256-GCM.
 *
 * @param encrypted - Encrypted metadata with IV (hex) and ciphertext (base64)
 * @param folderKey - 32-byte AES key for this folder
 * @returns Decrypted folder metadata object
 * @throws CryptoError if decryption fails (wrong key, corrupted data, etc.)
 */
export async function decryptFolderMetadata(
  encrypted: EncryptedFolderMetadata,
  folderKey: Uint8Array
): Promise<FolderMetadata> {
  // Decode IV and ciphertext
  const iv = hexToBytes(encrypted.iv);
  const ciphertext = Uint8Array.from(atob(encrypted.data), (c) => c.charCodeAt(0));

  // Decrypt with AES-256-GCM
  const plaintext = await decryptAesGcm(ciphertext, folderKey, iv);

  // Parse JSON back to metadata object
  // [SECURITY: MEDIUM-07] Validate the decrypted data before returning
  const parsed = JSON.parse(new TextDecoder().decode(plaintext));
  return validateFolderMetadata(parsed);
}
