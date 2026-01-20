/**
 * @cipherbox/crypto - AES-256-GCM Decryption
 *
 * Symmetric decryption for file content and folder metadata.
 * Uses Web Crypto API for hardware-accelerated decryption.
 */

import { CryptoError } from '../types';
import { AES_KEY_SIZE, AES_IV_SIZE, AES_GCM_ALGORITHM } from '../constants';

/**
 * Decrypt data encrypted with AES-256-GCM.
 *
 * Automatically verifies the authentication tag during decryption.
 * Throws on any failure (wrong key, modified ciphertext, wrong IV).
 *
 * @param ciphertext - Encrypted data including 16-byte authentication tag
 * @param key - 32-byte AES key (must match encryption key)
 * @param iv - 12-byte initialization vector (must match encryption IV)
 * @returns Decrypted plaintext
 * @throws CryptoError with generic message on any failure
 */
export async function decryptAesGcm(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  // Validate key size
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError('Decryption failed', 'INVALID_KEY_SIZE');
  }

  // Validate IV size
  if (iv.length !== AES_IV_SIZE) {
    throw new CryptoError('Decryption failed', 'INVALID_IV_SIZE');
  }

  try {
    // Import key for decryption
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: AES_GCM_ALGORITHM },
      false,
      ['decrypt']
    );

    // Decrypt - Web Crypto verifies auth tag and throws on mismatch
    const plaintext = await crypto.subtle.decrypt(
      { name: AES_GCM_ALGORITHM, iv },
      cryptoKey,
      ciphertext
    );

    return new Uint8Array(plaintext);
  } catch {
    // Generic error to prevent oracle attacks
    // Do NOT reveal whether auth tag failed, key was wrong, or IV mismatched
    throw new CryptoError('Decryption failed', 'DECRYPTION_FAILED');
  }
}
