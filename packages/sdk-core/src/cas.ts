/**
 * Generic CAS-retry helper for IPNS publish operations.
 *
 * Owns the resolve→encrypt→upload→CAS→409→merge→retry→ConflictError skeleton
 * for both file and folder publish paths. Domain-specific encode, decode, and
 * merge logic is injected as callbacks.
 *
 * Security: publishWithCas NEVER zeroes key material — callers are responsible
 * for zeroing after the call returns (T-47-01).
 */

import type { SdkContext } from './types';
import { createAndPublishIpnsRecord, resolveIpnsRecord } from './ipns';
import { is409, ConflictError } from './errors';

// Exponential backoff constants
const BACKOFF_BASE_MS = 100;
const BACKOFF_CAP_MS = 1500;

/** Exponential backoff with ±50% jitter. */
function retryDelayMs(attempt: number): number {
  const base = Math.min(BACKOFF_BASE_MS * 2 ** attempt, BACKOFF_CAP_MS);
  return base * (0.5 + Math.random()); // ±50% jitter => [0.5x, 1.5x)
}

/**
 * Generic CAS-retry publish helper.
 *
 * On success returns the published CID, new sequence number, final local data,
 * and any pruned CIDs accumulated across merge rounds.
 *
 * On 409 conflict: re-resolves authoritatively, fetches+decodes remote data,
 * calls merge(base, local, remote), then retries with the merged data.
 *
 * Throws ConflictError after maxAttempts unsuccessful publishes.
 * Rethrows non-409 errors immediately without retry.
 */
export async function publishWithCas<TData>(params: {
  ipnsName: string;
  ipnsPrivateKey: Uint8Array;
  ipnsPublicKey?: Uint8Array;
  sequenceNumber: bigint;
  ctx: SdkContext;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
  maxAttempts: number;
  backoff: boolean;
  /** Encode local state to IPFS and return the resulting CID. */
  encodeAndUpload: (local: TData) => Promise<string>;
  /** Decode remote data from IPFS using the given CID. */
  decodeRemote: (cid: string) => Promise<TData>;
  /**
   * Three-way merge returning merged data and optional pruned CIDs.
   *
   * `base` is `undefined` when the caller omits `baseData` (e.g. the latest-wins
   * file path, which ignores `base`); merge implementations that read `base`
   * must defend against `undefined`.
   */
  merge: (
    base: TData | undefined,
    local: TData,
    remote: TData
  ) => { merged: TData; prunedCids?: string[] };
  /** Initial local data for the first publish attempt. */
  localData: TData;
  /** Base snapshot for three-way merge. */
  baseData?: TData;
}): Promise<{
  cid: string;
  newSequenceNumber: bigint;
  publishedData: TData;
  prunedCids: string[];
}> {
  let currentSeq = params.sequenceNumber;
  let localData = params.localData;
  let lastRemoteSeq: bigint = params.sequenceNumber;
  let prunedCids: string[] = [];

  for (let attempt = 0; attempt < params.maxAttempts; attempt++) {
    // 1. Encode + upload (domain-specific, injected)
    const cid = await params.encodeAndUpload(localData);
    const newSeq = currentSeq + 1n;

    try {
      // 2. CAS publish with expectedSequenceNumber guard
      await createAndPublishIpnsRecord({
        ipnsPrivateKey: params.ipnsPrivateKey,
        ipnsPublicKey: params.ipnsPublicKey,
        ipnsName: params.ipnsName,
        metadataCid: cid,
        sequenceNumber: newSeq,
        encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
        keyEpoch: params.keyEpoch,
        expectedSequenceNumber: currentSeq.toString(),
        ctx: params.ctx,
      });
      return { cid, newSequenceNumber: newSeq, publishedData: localData, prunedCids };
    } catch (err) {
      if (!is409(err)) throw err;

      // 3. Re-resolve authoritatively — ignore seq hint in error body
      const resolved = await resolveIpnsRecord(params.ipnsName, params.ctx);
      if (!resolved) {
        throw new ConflictError(params.ipnsName, attempt + 1, lastRemoteSeq);
      }
      currentSeq = resolved.sequenceNumber;
      lastRemoteSeq = resolved.sequenceNumber;

      // 4. Fetch + decode remote
      const remoteData = await params.decodeRemote(resolved.cid);

      // 5. Three-way merge (domain-specific, injected)
      const { merged, prunedCids: extraPruned } = params.merge(
        params.baseData,
        localData,
        remoteData
      );
      localData = merged;
      prunedCids = [...new Set([...prunedCids, ...(extraPruned ?? [])])];

      // 6. After the final attempt, throw ConflictError
      if (attempt === params.maxAttempts - 1) {
        throw new ConflictError(params.ipnsName, params.maxAttempts, lastRemoteSeq);
      }

      // 7. Backoff + jitter before next attempt
      if (params.backoff) {
        await new Promise<void>((resolve) => setTimeout(resolve, retryDelayMs(attempt)));
      }
    }
  }

  // Unreachable — ConflictError is thrown inside the loop above on exhaustion
  throw new ConflictError(params.ipnsName, params.maxAttempts, lastRemoteSeq);
}
