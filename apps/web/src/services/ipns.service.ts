/**
 * IPNS Service - Record creation, publishing, and resolution
 *
 * Creates IPNS records locally using @cipherbox/crypto and publishes
 * via the backend API relay to delegated-ipfs.dev.
 */

import {
  createIpnsRecord,
  marshalIpnsRecord,
  verifyEd25519,
  IPNS_SIGNATURE_PREFIX,
  concatBytes,
} from '@cipherbox/crypto';
import {
  ipnsControllerPublishRecord,
  ipnsControllerPublishBatch,
  ipnsControllerResolveRecord,
} from '../api/ipns/ipns';
import type { PublishIpnsEntryDtoRecordType } from '../api/models/publishIpnsEntryDtoRecordType';

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
    metadataCid: string;
    encryptedIpnsPrivateKey?: string;
    keyEpoch?: number;
    recordType?: 'folder' | 'file';
  }>
): Promise<{ totalSucceeded: number; totalFailed: number }> {
  const response = await ipnsControllerPublishBatch({
    records: records.map((r) => ({
      ipnsName: r.ipnsName,
      record: r.recordBase64,
      metadataCid: r.metadataCid,
      encryptedIpnsPrivateKey: r.encryptedIpnsPrivateKey,
      keyEpoch: r.keyEpoch,
      recordType: r.recordType as PublishIpnsEntryDtoRecordType | undefined,
    })),
  });

  return {
    totalSucceeded: response.totalSucceeded,
    totalFailed: response.totalFailed,
  };
}

/**
 * Verify the Ed25519 signature on an IPNS record.
 * Per IPFS spec, the signature is over "ipns-signature:" + cborData.
 *
 * @param signatureV2 - base64 Ed25519 signature (64 bytes)
 * @param data - base64 CBOR data that was signed
 * @param pubKey - base64 raw Ed25519 public key (32 bytes)
 * @returns true if valid
 */
export async function verifyIpnsSignature(
  signatureV2: string,
  data: string,
  pubKey: string
): Promise<boolean> {
  const sigBytes = Uint8Array.from(atob(signatureV2), (c) => c.charCodeAt(0));
  const dataBytes = Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
  const pubKeyBytes = Uint8Array.from(atob(pubKey), (c) => c.charCodeAt(0));

  // Per IPFS IPNS spec, signature is over "ipns-signature:" + cborData
  const signedData = concatBytes(IPNS_SIGNATURE_PREFIX, dataBytes);
  return verifyEd25519(sigBytes, signedData, pubKeyBytes);
}

/**
 * Resolve an IPNS name to its current CID and sequence number.
 *
 * Calls backend API which relays to delegated-ipfs.dev for resolution.
 * When the response includes IPNS signature data (from delegated routing),
 * verifies the Ed25519 signature before trusting the CID.
 *
 * @param ipnsName - IPNS name to resolve (k51.../bafzaa... format)
 * @returns Current CID, sequence number, and signature verification status, or null if not found
 */
export async function resolveIpnsRecord(
  ipnsName: string
): Promise<{ cid: string; sequenceNumber: bigint; signatureVerified: boolean } | null> {
  try {
    const response = await ipnsControllerResolveRecord({ ipnsName });

    if (!response.success) {
      return null;
    }

    // Verify IPNS signature if all signature fields are present
    let signatureVerified = false;
    if (response.signatureV2 && response.data && response.pubKey) {
      const valid = await verifyIpnsSignature(response.signatureV2, response.data, response.pubKey);
      if (!valid) {
        throw new Error('IPNS signature verification failed - record may be tampered');
      }
      signatureVerified = true;
    } else {
      console.warn('IPNS resolve returned without signature data, skipping verification');
    }

    return {
      cid: response.cid,
      sequenceNumber: BigInt(response.sequenceNumber),
      signatureVerified,
    };
  } catch (error) {
    // 404 means IPNS name not found - return null
    // Other errors should propagate (including signature verification failures)
    if (error instanceof Error && (error as Error & { status?: number }).status === 404) {
      return null;
    }
    throw error;
  }
}
