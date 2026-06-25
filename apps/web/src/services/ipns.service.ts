/**
 * IPNS Service - Record creation, publishing, and resolution
 *
 * Creates IPNS records locally using @cipherbox/core and publishes
 * via the backend API relay to the delegated routing service.
 *
 * Resolution is delegated to sdk-core's resolveIpnsRecord, which carries
 * the CBOR cid/sequence binding (D-07/D-08, 58-01) and partial-fields
 * fail-closed check (D-02/D-03). The web axios instance is threaded via
 * SdkContext so the sdk-core function uses the same authenticated client.
 */

import { createIpnsRecord, marshalIpnsRecord } from '@cipherbox/core';
import { deriveEd25519PublicKey } from '@cipherbox/crypto';
import { ipnsControllerPublishRecord, ipnsControllerPublishBatch } from '@cipherbox/api-client';
import { resolveIpnsRecord as resolveIpnsRecordCore } from '@cipherbox/sdk-core';
import { apiAxios, apiUrl } from '../lib/api-config';
import { useAuthStore } from '../stores/auth.store';

/**
 * Create an IPNS record locally and publish via backend.
 *
 * The record is signed locally using the Ed25519 private key, then
 * the backend relays it to the IPFS network via delegated routing.
 *
 * @param params.ipnsPrivateKey - 32-byte Ed25519 private key seed
 * @param params.ipnsName - IPNS name (k51.../bafzaa... format)
 * @param params.metadataCid - CID of the encrypted metadata blob
 * @param params.sequenceNumber - Sequence number for this publish
 * @param params.encryptedIpnsPrivateKey - Hex ECIES-wrapped key for TEE (first publish only)
 * @param params.keyEpoch - TEE key epoch (required with encryptedIpnsPrivateKey)
 * @param params.expectedSequenceNumber - Pre-increment sequence number for conflict detection (folder records only)
 */
export async function createAndPublishIpnsRecord(params: {
  ipnsPrivateKey: Uint8Array;
  ipnsName: string;
  metadataCid: string;
  sequenceNumber: bigint;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
  expectedSequenceNumber?: string;
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
  const publicKeyBytes = deriveEd25519PublicKey(params.ipnsPrivateKey);

  // 3. Base64 encode for API transmission (loop-based to avoid call stack overflow on large records)
  let recordBinary = '';
  for (let i = 0; i < recordBytes.length; i++) {
    recordBinary += String.fromCharCode(recordBytes[i]);
  }
  const recordBase64 = btoa(recordBinary);
  let pkBinary = '';
  for (let i = 0; i < publicKeyBytes.length; i++) {
    pkBinary += String.fromCharCode(publicKeyBytes[i]);
  }
  const publicKey = btoa(pkBinary);

  // 4. Call backend API to relay to IPFS network
  const response = await ipnsControllerPublishRecord({
    ipnsName: params.ipnsName,
    record: recordBase64,
    publicKey,
    metadataCid: params.metadataCid,
    encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
    keyEpoch: params.keyEpoch,
    expectedSequenceNumber: params.expectedSequenceNumber,
  });

  return {
    success: response.success,
    sequenceNumber: BigInt(response.sequenceNumber),
  };
}

/**
 * Batch publish multiple IPNS records in a single API call.
 *
 * Sends all records (folder and/or file) to the batch endpoint,
 * which processes them with concurrency-limited parallelism.
 * Partial success is allowed: individual failures do not fail the batch.
 *
 * @param records - Array of IPNS record payloads to publish
 * @returns Success and failure counts
 */
export async function batchPublishIpnsRecords(
  records: Array<{
    ipnsName: string;
    recordBase64: string;
    publicKey?: string;
    metadataCid: string;
    encryptedIpnsPrivateKey?: string;
    keyEpoch?: number;
    /** Pre-increment sequence number for conflict detection (folder records only) */
    expectedSequenceNumber?: string;
  }>
): Promise<{ totalSucceeded: number; totalFailed: number }> {
  const response = await ipnsControllerPublishBatch({
    records: records.map((r) => ({
      ipnsName: r.ipnsName,
      record: r.recordBase64,
      publicKey: r.publicKey,
      metadataCid: r.metadataCid,
      encryptedIpnsPrivateKey: r.encryptedIpnsPrivateKey,
      keyEpoch: r.keyEpoch,
      expectedSequenceNumber: r.expectedSequenceNumber,
    })),
  });

  return {
    totalSucceeded: response.totalSucceeded,
    totalFailed: response.totalFailed,
  };
}

/**
 * Resolve an IPNS name to its current CID and sequence number.
 *
 * Delegates to the sdk-core resolveIpnsRecord chokepoint, which carries:
 * - Ed25519 signature verification (D-02/D-03)
 * - Partial-fields fail-closed check
 * - CBOR cid/sequence binding (D-07/D-08, 58-01)
 * - Public-key → IPNS name derivation check
 *
 * The web axios instance (apiAxios) is threaded via SdkContext so all API
 * calls use the same authenticated, token-refreshing client (D-13).
 * Perf instrumentation is provided by sdk-core's internal withPerf('ipns:resolve', …).
 *
 * @param ipnsName - IPNS name to resolve (k51.../bafzaa... format)
 * @returns Current CID, sequence number, and signature verification status, or null if not found
 */
export async function resolveIpnsRecord(
  ipnsName: string
): Promise<{ cid: string; sequenceNumber: bigint; signatureVerified: boolean } | null> {
  return resolveIpnsRecordCore(ipnsName, {
    apiUrl,
    getAccessToken: async () => useAuthStore.getState().accessToken || '',
    axiosInstance: apiAxios,
  });
}
