/**
 * @cipherbox/crypto - Random Generation Utilities
 *
 * Cryptographically secure random number generation using Web Crypto API.
 */

import { CryptoError } from '../types';
import { AES_KEY_SIZE, AES_IV_SIZE } from '../constants';

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
