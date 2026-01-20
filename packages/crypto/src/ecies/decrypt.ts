/**
 * @cipherbox/crypto - ECIES Key Unwrapping (Decryption)
 *
 * Unwraps symmetric keys using ECIES with secp256k1.
 * Uses eciesjs library which handles ECDH, HKDF, and AES-GCM internally.
 */

import { decrypt } from 'eciesjs';
import { CryptoError } from '../types';
import { SECP256K1_PRIVATE_KEY_SIZE } from '../constants';

/**
 * Unwrap a key using ECIES decryption.
 *
 * Decrypts a wrapped key using the recipient's private key.
 * Only succeeds if the key was wrapped with the corresponding public key.
 *
 * @param wrappedKey - ECIES ciphertext from wrapKey
 * @param privateKey - 32-byte secp256k1 private key
 * @returns Original unwrapped key
 * @throws CryptoError with generic message on any failure
 */
export async function unwrapKey(
  wrappedKey: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  // Validate private key size
  if (privateKey.length !== SECP256K1_PRIVATE_KEY_SIZE) {
    throw new CryptoError('Key unwrapping failed', 'INVALID_PRIVATE_KEY_SIZE');
  }

  try {
    // eciesjs decrypt handles:
    // 1. Extract ephemeral public key from ciphertext
    // 2. ECDH key agreement with private key
    // 3. HKDF key derivation
    // 4. AES-GCM decryption with auth tag verification
    const unwrapped = decrypt(privateKey, wrappedKey);
    // Convert Buffer to Uint8Array for consistent API
    return new Uint8Array(unwrapped);
  } catch {
    // Generic error to prevent oracle attacks
    // Do NOT reveal whether:
    // - Private key was wrong
    // - Ciphertext was modified
    // - Auth tag failed
    throw new CryptoError('Key unwrapping failed', 'KEY_UNWRAPPING_FAILED');
  }
}
