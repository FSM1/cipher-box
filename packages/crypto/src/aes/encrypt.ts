/**
 * @cipherbox/crypto - AES-256-GCM Encryption
 *
 * Symmetric encryption for file content and folder metadata.
 * Uses Web Crypto API for hardware-accelerated encryption.
 */

import { CryptoError } from '../types';
import { AES_KEY_SIZE, AES_IV_SIZE, AES_GCM_ALGORITHM } from '../constants';
import { importAesKey } from './import-key';

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
    // Copy to ensure proper ArrayBuffer (not SharedArrayBuffer)
    const ivBuffer = new Uint8Array(iv).buffer as ArrayBuffer;
    const plaintextBuffer = new Uint8Array(plaintext).buffer as ArrayBuffer;

    // Import key for encryption
    const cryptoKey = await importAesKey(key, { name: AES_GCM_ALGORITHM }, ['encrypt']);

    // Encrypt - Web Crypto appends 16-byte auth tag to ciphertext
    const ciphertext = await crypto.subtle.encrypt(
      { name: AES_GCM_ALGORITHM, iv: ivBuffer },
      cryptoKey,
      plaintextBuffer
    );

    return new Uint8Array(ciphertext);
  } catch {
    // Generic error to prevent oracle attacks
    throw new CryptoError('Encryption failed', 'ENCRYPTION_FAILED');
  }
}

/**
 * Encrypt data using AES-256-GCM with Additional Authenticated Data (AAD).
 *
 * The AAD is bound into the GCM authentication tag via Web Crypto
 * AesGcmParams.additionalData. Decryption will fail if the AAD does not match.
 *
 * This is the deterministic lower-level function — the caller supplies the IV.
 * Use sealAesGcmAad for the higher-level API that mints a fresh random IV.
 *
 * @param plaintext - Data to encrypt
 * @param key - 32-byte AES key
 * @param iv - 12-byte initialization vector (MUST be unique per encryption with the same key)
 * @param aad - Additional Authenticated Data bound into the auth tag (e.g. from buildNodeAad)
 * @returns Ciphertext including 16-byte authentication tag
 * @throws CryptoError with generic message on any failure
 */
export async function encryptAesGcmAad(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array
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
    // Copy to ensure proper ArrayBuffer (not SharedArrayBuffer)
    const ivBuffer = new Uint8Array(iv).buffer as ArrayBuffer;
    const plaintextBuffer = new Uint8Array(plaintext).buffer as ArrayBuffer;
    const aadBuffer = new Uint8Array(aad).buffer as ArrayBuffer;

    // Import key for encryption
    const cryptoKey = await importAesKey(key, { name: AES_GCM_ALGORITHM }, ['encrypt']);

    // Encrypt — AAD is bound into the GCM authentication tag via additionalData
    const ciphertext = await crypto.subtle.encrypt(
      { name: AES_GCM_ALGORITHM, iv: ivBuffer, additionalData: aadBuffer },
      cryptoKey,
      plaintextBuffer
    );

    return new Uint8Array(ciphertext);
  } catch {
    // Generic error to prevent oracle attacks
    throw new CryptoError('Encryption failed', 'ENCRYPTION_FAILED');
  }
}
