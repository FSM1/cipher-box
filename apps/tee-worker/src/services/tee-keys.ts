/**
 * TEE Key Derivation Service
 *
 * Derives deterministic secp256k1 keypairs per epoch.
 * - Simulator mode: HKDF-SHA256 from a fixed seed (development/testing)
 * - CVM mode: DstackClient.getKey() for hardware-backed derivation (production)
 */

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import * as secp from '@noble/secp256k1';

/** Cache public keys per epoch to avoid repeated derivation */
const publicKeyCache = new Map<number, Uint8Array>();

/**
 * Derive a deterministic secp256k1 keypair for a given epoch.
 *
 * In simulator mode, uses HKDF-SHA256 with a fixed seed.
 * In CVM mode, uses Phala dstack SDK for hardware-backed derivation.
 *
 * @param epoch - The key epoch number
 * @returns Object with publicKey (65 bytes, uncompressed) and privateKey (32 bytes)
 */
export async function getKeypair(
  epoch: number
): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  const mode = process.env.TEE_MODE || 'simulator';

  const env = process.env.CIPHERBOX_ENVIRONMENT;
  if (
    mode === 'simulator' &&
    (env === 'production' || (!env && process.env.NODE_ENV === 'production'))
  ) {
    throw new Error(
      'TEE_MODE=simulator is not allowed in production. Set TEE_MODE=cvm for production deployments, or set CIPHERBOX_ENVIRONMENT explicitly.'
    );
  }

  let privateKey: Uint8Array;

  if (mode === 'cvm') {
    // Production: Phala Cloud CVM with dstack SDK
    // Dynamic import -- @phala/dstack-sdk is only available inside CVM
    const { DstackClient } = await import('@phala/dstack-sdk');
    const client = new DstackClient();
    const keyResult = await client.getKey('cipherbox/ipns-republish', `epoch-${epoch}`);
    privateKey = keyResult.asUint8Array().slice(0, 32);
  } else {
    // Simulator: deterministic HKDF derivation from fixed seed
    const seed = new TextEncoder().encode('cipherbox-tee-simulator-seed');
    const salt = new TextEncoder().encode('cipherbox-dev');
    const info = new TextEncoder().encode(`epoch-${epoch}`);
    privateKey = hkdf(sha256, seed, salt, info, 32);
  }

  // Derive uncompressed public key (65 bytes, 0x04 prefix)
  const publicKey = secp.getPublicKey(privateKey, false);

  // Cache public key for this epoch
  publicKeyCache.set(epoch, publicKey);

  return { publicKey, privateKey };
}

/**
 * Get the cached public key for an epoch, or derive it.
 *
 * @param epoch - The key epoch number
 * @returns 65-byte uncompressed secp256k1 public key
 */
export async function getPublicKey(epoch: number): Promise<Uint8Array> {
  const cached = publicKeyCache.get(epoch);
  if (cached) {
    return cached;
  }

  const { publicKey } = await getKeypair(epoch);
  return publicKey;
}
