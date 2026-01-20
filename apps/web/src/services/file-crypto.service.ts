import {
  generateFileKey,
  generateIv,
  encryptAesGcm,
  wrapKey,
  clearBytes,
  bytesToHex,
} from '@cipherbox/crypto';

export type EncryptedFileResult = {
  ciphertext: Uint8Array;
  iv: string; // hex-encoded for API
  wrappedKey: string; // hex-encoded for storage
  originalSize: number;
  encryptedSize: number;
};

/**
 * Encrypt a file using AES-256-GCM with a random file key,
 * then wrap the file key with the user's public key using ECIES.
 *
 * @param file - The file to encrypt
 * @param userPublicKey - User's secp256k1 public key (65 bytes, uncompressed)
 * @returns Encrypted file data with wrapped key and IV
 */
export async function encryptFile(
  file: File,
  userPublicKey: Uint8Array
): Promise<EncryptedFileResult> {
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
  };
}
