/**
 * @cipherbox/crypto - AES-256-GCM Encryption
 *
 * Symmetric encryption for file content and folder metadata.
 * Uses Web Crypto API for hardware-accelerated encryption.
 */

import { CryptoError } from '../types';
import { AES_KEY_SIZE, AES_IV_SIZE, AES_GCM_ALGORITHM } from '../constants';

/**
 * Encrypt data using AES-256-GCM.
 *
 * Each encryption MUST use a unique IV with the same key.
 * Reusing IV+key pairs is catastrophic for AES-GCM security.
 *
 * @param plaintext - Data to encrypt
 * @param key - 32-byte AES key
 * @param iv - 12-byte initialization vector (MUST be unique per encryption)
 * @returns Ciphertext including 16-byte authentication tag
 * @throws CryptoError with generic message on any failure
 */
export async function encryptAesGcm(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  // Validate key size
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError('Encryption failed', 'INVALID_KEY_SIZE');
  }

  // Validate IV size
  if (iv.length !== AES_IV_SIZE) {
    throw new CryptoError('Encryption failed', 'INVALID_IV_SIZE');
  }

  try {
    // Import key for encryption
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: AES_GCM_ALGORITHM },
      false,
      ['encrypt']
    );

    // Encrypt - Web Crypto appends 16-byte auth tag to ciphertext
    const ciphertext = await crypto.subtle.encrypt(
      { name: AES_GCM_ALGORITHM, iv },
      cryptoKey,
      plaintext
    );

    return new Uint8Array(ciphertext);
  } catch {
    // Generic error to prevent oracle attacks
    throw new CryptoError('Encryption failed', 'ENCRYPTION_FAILED');
  }
}
