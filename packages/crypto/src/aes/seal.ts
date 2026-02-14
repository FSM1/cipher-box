/**
 * @cipherbox/crypto - AES-256-GCM Seal/Unseal
 *
 * Higher-level API that handles IV generation and binding automatically.
 * This prevents IV mismanagement by ensuring IV is always stored with ciphertext.
 *
 * Format: IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)
 */

import { CryptoError } from '../types';
import { AES_KEY_SIZE, AES_IV_SIZE, AES_TAG_SIZE } from '../constants';
import { generateIv } from '../utils/random';
import { concatBytes } from '../utils/encoding';
import { encryptAesGcm } from './encrypt';
import { decryptAesGcm } from './decrypt';

/** Minimum sealed data size: IV + auth tag (no plaintext) */
const MIN_SEALED_SIZE = AES_IV_SIZE + AES_TAG_SIZE;

/**
 * Seal data using AES-256-GCM with automatic IV generation.
 *
 * This is the recommended API for encryption. It automatically:
 * 1. Generates a fresh random IV
 * 2. Encrypts the plaintext
 * 3. Prepends the IV to the ciphertext
 *
 * The returned sealed data can be safely stored - the IV is included.
 *
 * @param plaintext - Data to encrypt
 * @param key - 32-byte AES key
 * @returns Sealed data: IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)
 * @throws CryptoError with generic message on any failure
 */
export async function sealAesGcm(plaintext: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  // Validate key size
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError('Encryption failed', 'INVALID_KEY_SIZE');
  }

  // Generate fresh IV for each seal operation
  const iv = generateIv();

  // Encrypt the plaintext
  const ciphertext = await encryptAesGcm(plaintext, key, iv);

  // Return IV || ciphertext (IV is always first 12 bytes)
  return concatBytes(iv, ciphertext);
}

/**
 * Unseal data encrypted with sealAesGcm.
 *
 * This is the recommended API for decryption. It automatically:
 * 1. Extracts the IV from the sealed data
 * 2. Decrypts and verifies the ciphertext
 *
 * @param sealed - Sealed data from sealAesGcm
 * @param key - 32-byte AES key (must match encryption key)
 * @returns Decrypted plaintext
 * @throws CryptoError with generic message on any failure
 */
export async function unsealAesGcm(sealed: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  // Validate key size
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError('Decryption failed', 'INVALID_KEY_SIZE');
  }

  // Validate minimum sealed data size (IV + auth tag)
  if (sealed.length < MIN_SEALED_SIZE) {
    throw new CryptoError('Decryption failed', 'DECRYPTION_FAILED');
  }

  // Extract IV (first 12 bytes)
  const iv = sealed.slice(0, AES_IV_SIZE);

  // Extract ciphertext (everything after IV)
  const ciphertext = sealed.slice(AES_IV_SIZE);

  // Decrypt and return plaintext
  return decryptAesGcm(ciphertext, key, iv);
}
