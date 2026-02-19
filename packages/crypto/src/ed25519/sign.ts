/**
 * @cipherbox/crypto - Ed25519 Signing
 *
 * Sign and verify operations using Ed25519.
 * Used for IPNS record signing.
 */

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { CryptoError } from '../types';
import {
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
} from '../constants';

// Enable sync methods (required for @noble/ed25519 v2.x)
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/**
 * Signs a message with an Ed25519 private key.
 *
 * @param message - The message to sign
 * @param privateKey - 32-byte Ed25519 private key
 * @returns 64-byte Ed25519 signature
 * @throws CryptoError if privateKey is invalid or signing fails
 */
export async function signEd25519(
  message: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  // Validate private key length
  if (privateKey.length !== ED25519_PRIVATE_KEY_SIZE) {
    throw new CryptoError('Signing failed', 'INVALID_PRIVATE_KEY_SIZE');
  }

  try {
    const signature = await ed.signAsync(message, privateKey);
    return signature;
  } catch {
    throw new CryptoError('Signing failed', 'SIGNING_FAILED');
  }
}

/**
 * Verifies an Ed25519 signature.
 *
 * @param signature - 64-byte Ed25519 signature
 * @param message - The original message
 * @param publicKey - 32-byte Ed25519 public key
 * @returns true if signature is valid, false otherwise
 */
export async function verifyEd25519(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  // Validate signature length
  if (signature.length !== ED25519_SIGNATURE_SIZE) {
    return false;
  }

  // Validate public key length
  if (publicKey.length !== ED25519_PUBLIC_KEY_SIZE) {
    return false;
  }

  try {
    return await ed.verifyAsync(signature, message, publicKey);
  } catch {
    // Return false instead of throwing for invalid signatures
    return false;
  }
}
