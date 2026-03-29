/**
 * IPNS Record Signing Service
 *
 * Delegates to @cipherbox/core for IPNS record creation and marshaling.
 * TEE-specific: Uses 48-hour record lifetime (vs 24h default) to provide
 * comfortable margin with 6-hour republish interval.
 */

import { createIpnsRecord, marshalIpnsRecord } from '@cipherbox/core';

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
  const record = await createIpnsRecord(
    ed25519PrivateKey,
    '/ipfs/' + cid,
    sequenceNumber,
    TEE_RECORD_LIFETIME_MS
  );
  return marshalIpnsRecord(record);
}
