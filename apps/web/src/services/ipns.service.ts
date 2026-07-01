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
 *
 * ROT-07: for rotation-participating nodes, `resolveIpnsRecord` additionally
 * gates the resolved seq/generation through the durable anti-rollback
 * high-water floor (`rotation-state.service.ts`, 68-06) via the SDK's
 * `enforceResolved` (68-01). This is strictly a pre-unseal pass/throw gate —
 * the high-water value it reads/writes is never fed into the read-key
 * unwrap's AAD generation input (Pitfall 5).
 */

import { createIpnsRecord, marshalIpnsRecord } from '@cipherbox/core';
import { deriveEd25519PublicKey } from '@cipherbox/crypto';
import { ipnsControllerPublishRecord, ipnsControllerPublishBatch } from '@cipherbox/api-client';
import { resolveIpnsRecord as resolveIpnsRecordCore } from '@cipherbox/sdk-core';
import { apiAxios, apiUrl } from '../lib/api-config';
import { useAuthStore } from '../stores/auth.store';
import { enforceResolved, seedFromGrant } from './rotation-state.service';

/**
 * Rotation-anti-rollback context for a resolve of a rotation-participating
 * node (a child reached via a `SealedChildRef`, or a share-root reached via
 * a grant). Omit entirely for non-rotation IPNS names (e.g. the vault key
 * blob, BYO-pinning config) — those have no `generation`/`versionFloor` and
 * are resolved without the enforceResolved gate.
 */
export type ResolveRotationContext = {
  /** Durable high-water key. Nodes are keyed by `ipnsName` (no separate node id — see SealedChildRef). */
  nodeId: string;
  /**
   * The reader's expected `generation` for this node: the parent
   * `SealedChildRef.generation` mirror, or the grant's `rootGeneration` for
   * a share-root (design §2.6). Never the node's own envelope generation.
   */
  generation: number;
  /** Owner-vouched seq floor from the `SealedChildRef.versionFloor` (or grant), applied on first contact. */
  versionFloor: number;
  /**
   * Owner-vouched generation floor to seed on first contact (e.g. a grant's
   * `rootGeneration`). Only raises the floor (monotonic-max) — never lowers it.
   */
  rootGeneration?: number;
};

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
 * ROT-07 (SC#4/D-05): when `rotation` context is supplied, the resolved
 * record is additionally gated through the durable anti-rollback high-water
 * floor before being returned. On first contact, `rotation.rootGeneration`
 * (if provided) seeds the generation floor from the owner-vouched grant
 * value. The SDK's `enforceResolved` then compares the resolved sequence
 * number and the caller-supplied `generation` against the durable floors and
 * `versionFloor`, throwing `SequenceRegressionError`/`GenerationRegressionError`
 * on any regression (never caught here — the caller/toast layer surfaces it)
 * or bumping the monotonic-max floors on pass. This is a pre-unseal gate
 * only: the high-water value is never threaded into the read-key unwrap's
 * AAD generation input.
 *
 * @param ipnsName - IPNS name to resolve (k51.../bafzaa... format)
 * @param rotation - Optional anti-rollback context for a rotation-participating node
 * @returns Current CID, sequence number, and signature verification status, or null if not found
 */
export async function resolveIpnsRecord(
  ipnsName: string,
  rotation?: ResolveRotationContext
): Promise<{ cid: string; sequenceNumber: bigint; signatureVerified: boolean } | null> {
  const resolved = await resolveIpnsRecordCore(ipnsName, {
    apiUrl,
    getAccessToken: async () => useAuthStore.getState().accessToken || '',
    axiosInstance: apiAxios,
  });

  if (!resolved || !rotation) {
    return resolved;
  }

  // Fail closed BEFORE any floor mutation: an absent-signature record
  // (signatureVerified=false, tolerated by D-03 for legacy names) must never
  // seed or bump a durable floor — a relay could otherwise forge a huge seq
  // and permanently DoS the node. Rotation-participating nodes are always
  // published signed, so an unverified record here is itself a red flag.
  if (!resolved.signatureVerified) {
    throw new Error(
      `IPNS resolve for rotation-participating node ${ipnsName} returned an unverified record — refusing to gate floors on it`
    );
  }
  // The durable floor stores JS numbers; a sequence beyond MAX_SAFE_INTEGER
  // would silently truncate through Number() and corrupt the floor.
  if (resolved.sequenceNumber > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(
      `IPNS sequence number for ${ipnsName} exceeds Number.MAX_SAFE_INTEGER — refusing lossy floor conversion`
    );
  }

  if (rotation.rootGeneration !== undefined) {
    await seedFromGrant(rotation.nodeId, rotation.rootGeneration);
  }

  await enforceResolved({
    nodeId: rotation.nodeId,
    seq: Number(resolved.sequenceNumber),
    generation: rotation.generation,
    versionFloor: rotation.versionFloor,
  });

  return resolved;
}
