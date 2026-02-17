import {
  generateFileKey,
  generateIv,
  encryptAesGcm,
  wrapKey,
  clearBytes,
  bytesToHex,
} from '@cipherbox/crypto';

import { selectEncryptionMode, encryptFileCtr } from './streaming-crypto.service';

export type EncryptedFileResult = {
  ciphertext: Uint8Array;
  iv: string; // hex-encoded for API
  wrappedKey: string; // hex-encoded for storage
  originalSize: number;
  encryptedSize: number;
  encryptionMode: 'GCM' | 'CTR';
};

/**
 * Encrypt a file using the appropriate encryption mode.
 *
 * Media files above 256KB use AES-256-CTR (streaming, random-access decryption).
 * All other files use AES-256-GCM (authenticated encryption).
 *
 * Mode selection is transparent to the caller -- both paths return the same
 * EncryptedFileResult type with the encryptionMode field set accordingly.
 *
 * @param file - The file to encrypt
 * @param userPublicKey - User's secp256k1 public key (65 bytes, uncompressed)
 * @returns Encrypted file data with wrapped key and IV
 */
export async function encryptFile(
  file: File,
  userPublicKey: Uint8Array
): Promise<EncryptedFileResult> {
  const mode = selectEncryptionMode(file);

  // CTR path: streaming 1MB chunks for media files
  if (mode === 'CTR') {
    return encryptFileCtr(file, userPublicKey);
  }

  // GCM path: full-buffer authenticated encryption
  // 1. Generate unique file key and IV
  const fileKey = generateFileKey();
  const iv = generateIv();

  // 2. Read file as ArrayBuffer
  const plaintext = new Uint8Array(await file.arrayBuffer());
  const originalSize = plaintext.length;

  // 3. Encrypt with AES-256-GCM
  const ciphertext = await encryptAesGcm(plaintext, fileKey, iv);

  // 4. Wrap file key with user's public key (ECIES)
  const wrappedKey = await wrapKey(fileKey, userPublicKey);

  // 5. Clear sensitive key from memory
  clearBytes(fileKey);

  return {
    ciphertext,
    iv: bytesToHex(iv),
    wrappedKey: bytesToHex(wrappedKey),
    originalSize,
    encryptedSize: ciphertext.length,
    encryptionMode: 'GCM' as const,
  };
}
