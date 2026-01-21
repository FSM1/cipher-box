/**
 * @cipherbox/crypto - IPNS Record Creation
 *
 * Creates IPNS records using the ipns npm package.
 * Handles conversion from @noble/ed25519 raw keys to libp2p format.
 */

import { createIPNSRecord as ipnsCreate, type IPNSRecord } from 'ipns';
import { privateKeyFromRaw } from '@libp2p/crypto/keys';
import * as ed from '@noble/ed25519';
import { CryptoError } from '../types';

/** Default IPNS record lifetime: 24 hours in milliseconds */
const DEFAULT_LIFETIME_MS = 24 * 60 * 60 * 1000;

/**
 * Creates an IPNS record signed with the given Ed25519 private key.
 *
 * The ipns package handles:
 * - CBOR encoding of record data
 * - V1 and V2 signature creation
 * - Proper validity timestamp formatting
 *
 * @param ed25519PrivateKey - 32-byte Ed25519 private key (seed) from @noble/ed25519
 * @param value - IPFS path to point to (e.g., "/ipfs/bafy...")
 * @param sequenceNumber - Monotonically increasing sequence number
 * @param lifetimeMs - Record validity lifetime in milliseconds (default: 24 hours)
 * @returns IPNS record ready for marshaling and publishing
 * @throws CryptoError if key conversion or record creation fails
 */
export async function createIpnsRecord(
  ed25519PrivateKey: Uint8Array,
  value: string,
  sequenceNumber: bigint,
  lifetimeMs: number = DEFAULT_LIFETIME_MS
): Promise<IPNSRecord> {
  // Validate private key size
  if (ed25519PrivateKey.length !== 32) {
    throw new CryptoError('Invalid Ed25519 private key size', 'INVALID_PRIVATE_KEY_SIZE');
  }

  // [SECURITY: MEDIUM-06] Validate sequence number is non-negative
  if (sequenceNumber < 0n) {
    throw new CryptoError('Sequence number must be non-negative', 'SIGNING_FAILED');
  }

  // Intermediate key material buffer - we'll zero this after use
  let libp2pKeyBytes: Uint8Array | null = null;

  try {
    // Convert 32-byte @noble/ed25519 private key to libp2p format:
    // libp2p expects 64 bytes: [privateKey (32) + publicKey (32)]
    const publicKey = ed.getPublicKey(ed25519PrivateKey);
    libp2pKeyBytes = new Uint8Array(64);
    libp2pKeyBytes.set(ed25519PrivateKey, 0);
    libp2pKeyBytes.set(publicKey, 32);

    // Convert to libp2p PrivateKey object
    const libp2pPrivateKey = privateKeyFromRaw(libp2pKeyBytes);

    // [SECURITY: MEDIUM-05] Clear intermediate key material immediately after conversion
    libp2pKeyBytes.fill(0);
    libp2pKeyBytes = null;

    // Create IPNS record using the ipns package
    // v1Compatible: true creates both V1 and V2 signatures for maximum compatibility
    const record = await ipnsCreate(libp2pPrivateKey, value, sequenceNumber, lifetimeMs, {
      v1Compatible: true,
    });

    return record;
  } catch (error) {
    // [SECURITY: MEDIUM-05] Ensure key material is cleared even on error
    if (libp2pKeyBytes) {
      libp2pKeyBytes.fill(0);
    }

    // Re-throw CryptoErrors as-is
    if (error instanceof CryptoError) {
      throw error;
    }
    // Wrap other errors
    throw new CryptoError('IPNS record creation failed', 'SIGNING_FAILED');
  }
}

// Re-export the IPNSRecord type for consumers
export type { IPNSRecord };
