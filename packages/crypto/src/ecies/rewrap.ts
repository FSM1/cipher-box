/**
 * @cipherbox/crypto - ECIES Key Re-Wrapping
 *
 * Re-wraps a key from one recipient to another using ECIES.
 * Used for user-to-user sharing: owner unwraps their key and
 * re-wraps it with the recipient's public key.
 *
 * The plaintext key is zeroed from memory after re-wrapping.
 */

import { unwrapKey } from './decrypt';
import { wrapKey } from './encrypt';
import { CryptoError } from '../types';

/**
 * Re-wrap a key from owner encryption to recipient encryption.
 *
 * Unwraps a key using the owner's private key, then re-wraps it
 * with the recipient's public key. The plaintext key is zeroed
 * from memory after re-wrapping.
 *
 * @param ownerWrappedKey - ECIES ciphertext wrapped with owner's public key
 * @param ownerPrivateKey - 32-byte secp256k1 private key of the owner
 * @param recipientPublicKey - 65-byte uncompressed secp256k1 public key of the recipient
 * @returns Key re-wrapped for the recipient
 * @throws CryptoError with code 'KEY_REWRAP_FAILED' on any failure
 */
export async function reWrapKey(
  ownerWrappedKey: Uint8Array,
  ownerPrivateKey: Uint8Array,
  recipientPublicKey: Uint8Array
): Promise<Uint8Array> {
  let plainKey: Uint8Array | null = null;

  try {
    // 1. Unwrap with owner's private key
    plainKey = await unwrapKey(ownerWrappedKey, ownerPrivateKey);

    // 2. Re-wrap with recipient's public key
    const reWrapped = await wrapKey(plainKey, recipientPublicKey);

    // 3. Zero the plaintext key
    plainKey.fill(0);

    return reWrapped;
  } catch {
    // Zero the plaintext key if it was successfully unwrapped
    if (plainKey) {
      plainKey.fill(0);
    }

    // Generic error to prevent information leakage
    throw new CryptoError('Key re-wrapping failed', 'KEY_REWRAP_FAILED');
  }
}
