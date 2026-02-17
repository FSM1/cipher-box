/**
 * @cipherbox/crypto - AES-256-CTR Encryption
 *
 * Symmetric encryption for media file content using CTR mode.
 * CTR mode enables random-access decryption (any byte range without
 * processing preceding bytes), required for Service Worker streaming.
 *
 * Uses Web Crypto API for hardware-accelerated encryption.
 *
 * SECURITY NOTE: AES-CTR does NOT provide authentication (unlike GCM).
 * The caller is responsible for integrity verification via separate
 * mechanisms (e.g., IPFS content addressing provides integrity).
 */

import { CryptoError } from '../types';
import { AES_KEY_SIZE, AES_CTR_IV_SIZE, AES_CTR_ALGORITHM, AES_CTR_LENGTH } from '../constants';

/**
 * Encrypt data using AES-256-CTR.
 *
 * Each encryption MUST use a unique IV (nonce + counter) with the same key.
 * Reusing nonce+key pairs is catastrophic for AES-CTR security.
 *
 * CTR output is the same size as the input (no authentication tag).
 *
 * @param plaintext - Data to encrypt
 * @param key - 32-byte AES key
 * @param iv - 16-byte counter block (8-byte nonce + 8-byte counter)
 * @returns Ciphertext (same size as plaintext)
 * @throws CryptoError with generic message on any failure
 */
export async function encryptAesCtr(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  // Validate key size
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError('Encryption failed', 'INVALID_KEY_SIZE');
  }

  // Validate IV size
  if (iv.length !== AES_CTR_IV_SIZE) {
    throw new CryptoError('Encryption failed', 'INVALID_IV_SIZE');
  }

  try {
    // Copy to ensure proper ArrayBuffer (not SharedArrayBuffer)
    const keyBuffer = new Uint8Array(key).buffer as ArrayBuffer;
    const ivBuffer = new Uint8Array(iv);
    const plaintextBuffer = new Uint8Array(plaintext).buffer as ArrayBuffer;

    // Import key for encryption
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: AES_CTR_ALGORITHM },
      false,
      ['encrypt']
    );

    // Encrypt - CTR output is same size as input (XOR-based stream cipher)
    const ciphertext = await crypto.subtle.encrypt(
      { name: AES_CTR_ALGORITHM, counter: ivBuffer, length: AES_CTR_LENGTH },
      cryptoKey,
      plaintextBuffer
    );

    return new Uint8Array(ciphertext);
  } catch {
    // Generic error to prevent oracle attacks
    throw new CryptoError('Encryption failed', 'ENCRYPTION_FAILED');
  }
}
