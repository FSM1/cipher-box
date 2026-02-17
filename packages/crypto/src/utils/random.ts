/**
 * @cipherbox/crypto - Random Generation Utilities
 *
 * Cryptographically secure random number generation using Web Crypto API.
 */

import { CryptoError } from '../types';
import { AES_KEY_SIZE, AES_IV_SIZE, AES_CTR_IV_SIZE, AES_CTR_NONCE_SIZE } from '../constants';

/**
 * Generate cryptographically secure random bytes.
 *
 * @param length - Number of bytes to generate
 * @returns Random bytes
 * @throws CryptoError if crypto.getRandomValues is unavailable
 */
export function generateRandomBytes(length: number): Uint8Array {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new CryptoError(
      'Secure random generation unavailable - requires secure context (HTTPS or localhost)',
      'RANDOM_GENERATION_FAILED'
    );
  }

  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Generate a random 256-bit file key for AES-GCM encryption.
 *
 * Each file must use a unique key - never reuse keys across files.
 *
 * @returns 32-byte random key
 */
export function generateFileKey(): Uint8Array {
  return generateRandomBytes(AES_KEY_SIZE);
}

/**
 * Generate a random 96-bit IV for AES-GCM encryption.
 *
 * Each encryption operation must use a unique IV with the same key.
 * NEVER reuse an IV with the same key - this would be catastrophic for security.
 *
 * @returns 12-byte random IV
 */
export function generateIv(): Uint8Array {
  return generateRandomBytes(AES_IV_SIZE);
}

/**
 * Generate a 16-byte IV for AES-256-CTR encryption.
 *
 * The IV is structured as two 8-byte halves:
 * - Bytes [0..7]:  Cryptographically random nonce (unique per file)
 * - Bytes [8..15]: Counter starting at 0 (incremented by Web Crypto per block)
 *
 * The 8/8 nonce/counter split with 64-bit counter supports files up to
 * 2^64 * 16 bytes (effectively unlimited). The counter starts at zero so
 * random-access offset calculation is simply `blockIndex = byteOffset / 16`.
 *
 * NEVER reuse a nonce with the same key -- CTR nonce reuse is catastrophic.
 *
 * @returns 16-byte IV with random nonce and zero counter
 */
export function generateCtrIv(): Uint8Array {
  const iv = new Uint8Array(AES_CTR_IV_SIZE);
  // Random nonce in first 8 bytes
  const nonce = generateRandomBytes(AES_CTR_NONCE_SIZE);
  iv.set(nonce, 0);
  // Last 8 bytes remain zero (counter starts at 0)
  return iv;
}
