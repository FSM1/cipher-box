/**
 * IPNS Record Signing Service
 *
 * Replicates IPNS signing logic from @cipherbox/crypto for standalone TEE deployment.
 * Creates and signs IPNS records using Ed25519 keys, with immediate key zeroing.
 *
 * TEE-specific: Uses 48-hour record lifetime (vs 24h for client-published records)
 * to provide comfortable margin with 6-hour republish interval.
 */

import { createIPNSRecord } from 'ipns';
import { marshalIPNSRecord } from 'ipns';
import { privateKeyFromRaw } from '@libp2p/crypto/keys';
import * as ed from '@noble/ed25519';

/** 48-hour IPNS record lifetime for TEE-republished records */
const TEE_RECORD_LIFETIME_MS = 48 * 60 * 60 * 1000;

/**
 * Sign an IPNS record with an Ed25519 private key.
 *
 * Creates a V1+V2 compatible IPNS record pointing to the given CID,
 * with a 48-hour lifetime and the specified sequence number.
 *
 * @param ed25519PrivateKey - 32-byte Ed25519 private key (seed)
 * @param cid - IPFS CID string to point to (without /ipfs/ prefix)
 * @param sequenceNumber - Monotonically increasing sequence number
 * @returns Marshaled (protobuf-encoded) signed IPNS record bytes
 */
export async function signIpnsRecord(
  ed25519PrivateKey: Uint8Array,
  cid: string,
  sequenceNumber: bigint
): Promise<Uint8Array> {
  // Derive Ed25519 public key from private key
  const publicKey = await ed.getPublicKeyAsync(ed25519PrivateKey);

  // Create libp2p-format 64-byte key: [privateKey (32) + publicKey (32)]
  const libp2pKeyBytes = new Uint8Array(64);
  libp2pKeyBytes.set(ed25519PrivateKey, 0);
  libp2pKeyBytes.set(publicKey, 32);

  // Convert to libp2p PrivateKey object
  const libp2pPrivateKey = privateKeyFromRaw(libp2pKeyBytes);

  // Zero intermediate key material immediately
  libp2pKeyBytes.fill(0);

  // Create IPNS record with V1+V2 signatures and 48h lifetime
  const record = await createIPNSRecord(
    libp2pPrivateKey,
    '/ipfs/' + cid,
    sequenceNumber,
    TEE_RECORD_LIFETIME_MS,
    { v1Compatible: true }
  );

  // Marshal to protobuf bytes for transmission
  return marshalIPNSRecord(record);
}
