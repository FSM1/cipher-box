/**
 * IPNS Service - Record creation, publishing, and resolution
 *
 * Extracted from: apps/web/src/services/ipns.service.ts
 * Change: Uses @cipherbox/api-client generated functions instead of web app local imports.
 * The ipns.service.ts was already clean (no store deps), so the extraction is straightforward.
 */

import { createIpnsRecord, marshalIpnsRecord, IPNS_SIGNATURE_PREFIX } from '@cipherbox/core';
import {
  verifyEd25519,
  concatBytes,
  deriveEd25519PublicKey,
  deriveIpnsName,
} from '@cipherbox/crypto';
import {
  ipnsControllerPublishRecord,
  ipnsControllerPublishBatch,
  ipnsControllerResolveRecord,
} from '@cipherbox/api-client';
import type { PublishIpnsEntryDtoRecordType } from '@cipherbox/api-client';
import type { SdkContext } from '../types';
import { withPerf } from '../perf';

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
  ipnsPublicKey?: Uint8Array;
  ipnsName: string;
  metadataCid: string;
  sequenceNumber: bigint;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
  expectedSequenceNumber?: string;
  ctx?: SdkContext;
}): Promise<{ success: boolean; sequenceNumber: bigint }> {
  return withPerf('ipns:publish', async () => {
    try {
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
      const publicKeyBytes = params.ipnsPublicKey ?? deriveEd25519PublicKey(params.ipnsPrivateKey);

      // 3. Base64 encode for API transmission (loop-based to avoid call stack overflow on large records)
      let binary = '';
      for (let i = 0; i < recordBytes.length; i++) {
        binary += String.fromCharCode(recordBytes[i]);
      }
      const recordBase64 = btoa(binary);
      binary = '';
      for (let i = 0; i < publicKeyBytes.length; i++) {
        binary += String.fromCharCode(publicKeyBytes[i]);
      }
      const publicKey = btoa(binary);

      // 4. Call backend API to relay to IPFS network
      const apiOptions = params.ctx?.axiosInstance
        ? { _axiosInstance: params.ctx.axiosInstance }
        : undefined;
      const response = await ipnsControllerPublishRecord(
        {
          ipnsName: params.ipnsName,
          record: recordBase64,
          publicKey,
          metadataCid: params.metadataCid,
          encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
          keyEpoch: params.keyEpoch,
          expectedSequenceNumber: params.expectedSequenceNumber,
        },
        apiOptions
      );

      return {
        success: response.success,
        sequenceNumber: BigInt(response.sequenceNumber),
      };
    } finally {
      // T-47-01 / D-05: caller-owns-key convention — zero the private key on all exit paths
      // (success and throw). publishWithCas / callee functions must NOT zero; only the
      // buffer-owning boundary (this function) does.
      params.ipnsPrivateKey.fill(0);
    }
  });
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
  }>,
  ctx?: SdkContext
): Promise<{ totalSucceeded: number; totalFailed: number }> {
  return withPerf('ipns:batch-publish', async () => {
    const apiOptions = ctx?.axiosInstance ? { _axiosInstance: ctx.axiosInstance } : undefined;
    const response = await ipnsControllerPublishBatch(
      {
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
      },
      apiOptions
    );

    return {
      totalSucceeded: response.totalSucceeded,
      totalFailed: response.totalFailed,
    };
  });
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
  ipnsName: string,
  ctx?: SdkContext
): Promise<{ cid: string; sequenceNumber: bigint; signatureVerified: boolean } | null> {
  return withPerf('ipns:resolve', async () => {
    try {
      const apiOptions = ctx?.axiosInstance ? { _axiosInstance: ctx.axiosInstance } : undefined;
      const response = await ipnsControllerResolveRecord({ ipnsName }, apiOptions);

      if (!response.success) {
        return null;
      }

      // Verify IPNS signature if all signature fields are present
      let signatureVerified = false;
      if (response.signatureV2 && response.data && response.pubKey) {
        const valid = await verifyIpnsSignature(
          response.signatureV2,
          response.data,
          response.pubKey
        );
        if (!valid) {
          throw new Error('IPNS signature verification failed - record may be tampered');
        }

        // Verify the returned public key derives to the requested IPNS name
        const pubKeyBytes = Uint8Array.from(atob(response.pubKey), (c) => c.charCodeAt(0));
        const derivedName = await deriveIpnsName(pubKeyBytes);
        if (derivedName !== ipnsName) {
          throw new Error(
            'IPNS public key does not match requested name - possible key substitution'
          );
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
      if (error instanceof Error) {
        const anyError = error as Error & { status?: number; response?: { status?: number } };
        const status = anyError.status ?? anyError.response?.status;
        if (status === 404) {
          return null;
        }
      }
      throw error;
    }
  });
}
