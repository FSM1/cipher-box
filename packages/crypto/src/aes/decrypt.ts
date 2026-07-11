/**
 * @cipherbox/crypto - AES-256-GCM Decryption
 *
 * Symmetric decryption for file content and folder metadata.
 * Uses Web Crypto API for hardware-accelerated decryption.
 */

import { CryptoError } from '../types';
import { AES_KEY_SIZE, AES_IV_SIZE, AES_TAG_SIZE, AES_GCM_ALGORITHM } from '../constants';
import { importAesKey } from './import-key';

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

  // Validate minimum ciphertext size (at least auth tag)
  if (ciphertext.length < AES_TAG_SIZE) {
    throw new CryptoError('Decryption failed', 'DECRYPTION_FAILED');
  }

  try {
    // Copy to ensure proper ArrayBuffer (not SharedArrayBuffer)
    const ivBuffer = new Uint8Array(iv).buffer as ArrayBuffer;
    const ciphertextBuffer = new Uint8Array(ciphertext).buffer as ArrayBuffer;

    // Import key for decryption
    const cryptoKey = await importAesKey(key, { name: AES_GCM_ALGORITHM }, ['decrypt']);

    // Decrypt - Web Crypto verifies auth tag and throws on mismatch
    const plaintext = await crypto.subtle.decrypt(
      { name: AES_GCM_ALGORITHM, iv: ivBuffer },
      cryptoKey,
      ciphertextBuffer
    );

    return new Uint8Array(plaintext);
  } catch {
    // Generic error to prevent oracle attacks
    // Do NOT reveal whether auth tag failed, key was wrong, or IV mismatched
    throw new CryptoError('Decryption failed', 'DECRYPTION_FAILED');
  }
}

/**
 * Decrypt data encrypted with encryptAesGcmAad (AES-256-GCM + AAD).
 *
 * The AAD must match what was used during encryption; any mismatch causes
 * authentication failure and the function throws. This prevents an AAD-transplant
 * attack where a sealed blob is replayed under a different node identity.
 *
 * @param ciphertext - Encrypted data including 16-byte authentication tag
 * @param key - 32-byte AES key (must match encryption key)
 * @param iv - 12-byte initialization vector (must match encryption IV)
 * @param aad - Additional Authenticated Data (must exactly match encryption AAD)
 * @returns Decrypted plaintext
 * @throws CryptoError with generic message on any failure (wrong key, wrong AAD, modified ciphertext)
 */
export async function decryptAesGcmAad(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> {
  // Validate key size
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError('Decryption failed', 'INVALID_KEY_SIZE');
  }

  // Validate IV size
  if (iv.length !== AES_IV_SIZE) {
    throw new CryptoError('Decryption failed', 'INVALID_IV_SIZE');
  }

  // Validate minimum ciphertext size (at least auth tag)
  if (ciphertext.length < AES_TAG_SIZE) {
    throw new CryptoError('Decryption failed', 'DECRYPTION_FAILED');
  }

  try {
    // Copy to ensure proper ArrayBuffer (not SharedArrayBuffer)
    const ivBuffer = new Uint8Array(iv).buffer as ArrayBuffer;
    const ciphertextBuffer = new Uint8Array(ciphertext).buffer as ArrayBuffer;
    const aadBuffer = new Uint8Array(aad).buffer as ArrayBuffer;

    // Import key for decryption
    const cryptoKey = await importAesKey(key, { name: AES_GCM_ALGORITHM }, ['decrypt']);

    // Decrypt — Web Crypto verifies auth tag (which covers the AAD) and throws on mismatch
    const plaintext = await crypto.subtle.decrypt(
      { name: AES_GCM_ALGORITHM, iv: ivBuffer, additionalData: aadBuffer },
      cryptoKey,
      ciphertextBuffer
    );

    return new Uint8Array(plaintext);
  } catch {
    // Generic error to prevent oracle attacks
    // Do NOT reveal whether auth tag failed, AAD was wrong, key was wrong, or IV mismatched
    throw new CryptoError('Decryption failed', 'DECRYPTION_FAILED');
  }
}
