/**
 * IPNS Service - Record creation, publishing, and resolution
 *
 * Creates IPNS records locally using @cipherbox/core and publishes
 * via the backend API relay to the delegated routing service.
 */

import { createIpnsRecord, marshalIpnsRecord, IPNS_SIGNATURE_PREFIX } from '@cipherbox/core';
import {
  verifyEd25519,
  concatBytes,
  deriveIpnsName,
  deriveEd25519PublicKey,
} from '@cipherbox/crypto';
import {
  ipnsControllerPublishRecord,
  ipnsControllerPublishBatch,
  ipnsControllerResolveRecord,
} from '@cipherbox/api-client';
import type { PublishIpnsEntryDtoRecordType } from '@cipherbox/api-client';
import { logger } from '../lib/logger';

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
    recordType?: 'folder' | 'file';
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
      recordType: r.recordType as PublishIpnsEntryDtoRecordType | undefined,
      expectedSequenceNumber: r.expectedSequenceNumber,
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
 * Calls backend API which relays to the delegated routing service for resolution.
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

    // Verify IPNS signature if all signature fields are present.
    // D-02: present-but-invalid → throw (fail closed; mirrors sdk-core behavior)
    // D-03: ALL fields absent → allow + flag (signatureVerified=false); legacy records
    //        are allowed because the DB CID is authoritative.
    // Partial signature fields (some but not all three present) → fail closed: a record
    // that carries unverifiable signature material must not be downgraded to the legacy
    // allow path, or an attacker could strip fields to bypass D-02.
    let signatureVerified = false;
    const { signatureV2, data, pubKey } = response;
    if (signatureV2 || data || pubKey) {
      if (!signatureV2 || !data || !pubKey) {
        throw new Error(
          'IPNS resolve returned incomplete signature data - record cannot be verified'
        );
      }

      const valid = await verifyIpnsSignature(signatureV2, data, pubKey);
      if (!valid) {
        throw new Error('IPNS signature verification failed - record may be tampered');
      }

      // Verify the returned public key derives to the requested IPNS name
      const pubKeyBytes = Uint8Array.from(atob(pubKey), (c) => c.charCodeAt(0));
      const derivedName = await deriveIpnsName(pubKeyBytes);
      if (derivedName !== ipnsName) {
        throw new Error(
          'IPNS public key does not match requested name - possible key substitution'
        );
      }

      signatureVerified = true;
    } else {
      // D-03: all signature fields absent (legacy record) — allow + flag
      logger.warn('[IPNS] IPNS resolve returned without signature data, skipping verification');
    }

    return {
      cid: response.cid,
      sequenceNumber: BigInt(response.sequenceNumber),
      signatureVerified,
    };
  } catch (error) {
    // 404 means IPNS name not found - return null
    // Other errors (network, API) should propagate
    if (error instanceof Error && (error as Error & { status?: number }).status === 404) {
      return null;
    }
    throw error;
  }
}
