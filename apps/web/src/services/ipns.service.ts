/**
 * IPNS Service - Record creation and publishing
 *
 * Creates IPNS records locally using @cipherbox/crypto and publishes
 * via the backend API relay to delegated-ipfs.dev.
 */

import { createIpnsRecord, marshalIpnsRecord } from '@cipherbox/crypto';
import { ipnsControllerPublishRecord } from '../api/ipns/ipns';

/**
 * Create an IPNS record locally and publish via backend.
 *
 * The record is signed locally using the Ed25519 private key, then
 * the backend relays it to the IPFS network via delegated routing.
 *
 * @param params.ipnsPrivateKey - Ed25519 private key (64 bytes in libp2p format)
 * @param params.ipnsName - IPNS name (k51.../bafzaa... format)
 * @param params.metadataCid - CID of the encrypted metadata blob
 * @param params.sequenceNumber - Current sequence number (will be incremented before publish)
 * @param params.encryptedIpnsPrivateKey - Hex ECIES-wrapped key for TEE (first publish only)
 * @param params.keyEpoch - TEE key epoch (required with encryptedIpnsPrivateKey)
 */
export async function createAndPublishIpnsRecord(params: {
  ipnsPrivateKey: Uint8Array;
  ipnsName: string;
  metadataCid: string;
  sequenceNumber: bigint;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
}): Promise<{ success: boolean; sequenceNumber: bigint }> {
  // 1. Create IPNS record pointing to /ipfs/{metadataCid}
  // 24 hour lifetime (will be republished by TEE every 3 hours)
  const record = await createIpnsRecord(
    params.ipnsPrivateKey,
    `/ipfs/${params.metadataCid}`,
    params.sequenceNumber,
    24 * 60 * 60 * 1000 // 24 hours in ms
  );

  // 2. Marshal to bytes for transport
  const recordBytes = marshalIpnsRecord(record);

  // 3. Base64 encode for API transmission
  const recordBase64 = btoa(String.fromCharCode(...recordBytes));

  // 4. Call backend API to relay to IPFS network
  const response = await ipnsControllerPublishRecord({
    ipnsName: params.ipnsName,
    record: recordBase64,
    metadataCid: params.metadataCid,
    encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
    keyEpoch: params.keyEpoch,
  });

  return {
    success: response.success,
    sequenceNumber: BigInt(response.sequenceNumber),
  };
}

/**
 * Resolve an IPNS name to its current CID and sequence number.
 *
 * For now, this returns null - actual IPNS resolution via Pinata gateway
 * or IPFS network will be implemented in Phase 7 (Multi-Device Sync).
 *
 * @param ipnsName - IPNS name to resolve (k51.../bafzaa... format)
 * @returns Current CID and sequence number, or null if not found
 */
export async function resolveIpnsRecord(
  _ipnsName: string
): Promise<{ cid: string; sequenceNumber: bigint } | null> {
  // Stub implementation - actual resolution deferred to Phase 7
  // Will use Pinata gateway or direct IPFS gateway for resolution
  return null;
}
