/**
 * @cipherbox/crypto - Ed25519 Key Generation
 *
 * Generates Ed25519 keypairs for IPNS record signing.
 * Each folder in CipherBox has its own Ed25519 keypair.
 */

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { CryptoError } from '../types';
import { ED25519_PRIVATE_KEY_SIZE } from '../constants';

// Enable sync methods (required for @noble/ed25519 v2.x)
// This configures the library to use synchronous SHA-512 hashing
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/**
 * Ed25519 keypair for IPNS operations.
 */
export type Ed25519Keypair = {
  /** 32-byte Ed25519 public key */
  publicKey: Uint8Array;
  /** 32-byte Ed25519 private key (seed) */
  privateKey: Uint8Array;
};

/**
 * Generates a new Ed25519 keypair.
 *
 * @returns Ed25519 keypair with 32-byte public and private keys
 */
export function generateEd25519Keypair(): Ed25519Keypair {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = ed.getPublicKey(privateKey);

  return {
    publicKey,
    privateKey,
  };
}

/**
 * Derives the Ed25519 public key from a 32-byte private key seed.
 *
 * @param privateKey - 32-byte Ed25519 private key seed
 * @returns 32-byte Ed25519 public key
 * @throws CryptoError if privateKey is not 32 bytes
 */
export function deriveEd25519PublicKey(privateKey: Uint8Array): Uint8Array {
  if (privateKey.length !== ED25519_PRIVATE_KEY_SIZE) {
    throw new CryptoError(
      'Invalid private key size for public key derivation',
      'INVALID_PRIVATE_KEY_SIZE'
    );
  }
  return ed.getPublicKey(privateKey);
}
