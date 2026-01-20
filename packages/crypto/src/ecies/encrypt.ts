/**
 * @cipherbox/crypto - ECIES Key Wrapping (Encryption)
 *
 * Wraps symmetric keys using ECIES with secp256k1.
 * Uses eciesjs library which handles ephemeral keys, ECDH, HKDF, and AES-GCM internally.
 */

import { encrypt } from 'eciesjs';
import { CryptoError } from '../types';
import { SECP256K1_PUBLIC_KEY_SIZE } from '../constants';

/**
 * Wrap a key using ECIES encryption.
 *
 * Encrypts a symmetric key (or any data) to a recipient's public key.
 * Only the holder of the corresponding private key can unwrap it.
 *
 * Each call produces different ciphertext due to ephemeral key generation.
 *
 * @param key - Data to wrap (typically a 32-byte file key)
 * @param recipientPublicKey - 65-byte uncompressed secp256k1 public key
 * @returns Wrapped key ciphertext
 * @throws CryptoError with generic message on any failure
 */
export async function wrapKey(
  key: Uint8Array,
  recipientPublicKey: Uint8Array
): Promise<Uint8Array> {
  // Validate public key size (uncompressed secp256k1)
  if (recipientPublicKey.length !== SECP256K1_PUBLIC_KEY_SIZE) {
    throw new CryptoError('Key wrapping failed', 'INVALID_PUBLIC_KEY_SIZE');
  }

  // Validate uncompressed public key prefix (0x04)
  if (recipientPublicKey[0] !== 0x04) {
    throw new CryptoError('Key wrapping failed', 'INVALID_PUBLIC_KEY_SIZE');
  }

  try {
    // eciesjs encrypt handles:
    // 1. Generate ephemeral keypair
    // 2. ECDH key agreement
    // 3. HKDF key derivation
    // 4. AES-GCM encryption
    // 5. Return: ephemeral_pubkey || ciphertext || tag
    const wrapped = encrypt(recipientPublicKey, key);
    return wrapped;
  } catch {
    // Generic error to prevent information leakage
    throw new CryptoError('Key wrapping failed', 'KEY_WRAPPING_FAILED');
  }
}
