/**
 * @cipherbox/crypto - Folder Metadata Encryption
 *
 * Encrypts and decrypts folder metadata using AES-256-GCM.
 * Folder metadata is JSON serialized before encryption.
 */

import { encryptAesGcm, decryptAesGcm } from '../aes';
import { generateIv, bytesToHex, hexToBytes } from '../utils';
import type { FolderMetadata, EncryptedFolderMetadata } from './types';

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
  return {
    iv: bytesToHex(iv),
    data: btoa(String.fromCharCode(...ciphertext)),
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
  return JSON.parse(new TextDecoder().decode(plaintext)) as FolderMetadata;
}
