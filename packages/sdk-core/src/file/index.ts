/**
 * File Metadata Service - Per-file IPNS operations
 *
 * Extracted from: apps/web/src/services/file-metadata.service.ts
 * Change: teeKeys passed explicitly instead of read from useAuthStore.
 * Change: IPFS/IPNS operations use sdk-core internal modules instead of web app imports.
 */

import {
  generateFileIpnsKeypair,
  encryptFileMetadata,
  decryptFileMetadata,
  createIpnsRecord,
  marshalIpnsRecord,
  type FileMetadata,
  type EncryptedFileMetadata,
  type VersionEntry,
} from '@cipherbox/core';
import { wrapKey, bytesToHex, hexToBytes } from '@cipherbox/crypto';
import type { SdkContext, TeeKeys } from '../types';
import { addToIpfs, fetchFromIpfs } from '../ipfs';
import { resolveIpnsRecord, createAndPublishIpnsRecord } from '../ipns';
import { ConflictError } from '../errors';

/** IPNS record lifetime: 24 hours in milliseconds */
const IPNS_LIFETIME_MS = 24 * 60 * 60 * 1000;

/** Maximum number of past versions retained per file (VER-04) */
const MAX_VERSIONS_PER_FILE = 10;

/** Safe base64 encoding that avoids call stack overflow from spread operator */
function uint8ToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/** Record payload ready for batch publish */
export type FileIpnsRecordPayload = {
  ipnsName: string;
  recordBase64: string;
  publicKey?: string;
  metadataCid: string;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
};

/**
 * Merge two VersionEntry arrays into a single deduped, sorted, capped result.
 *
 * Algorithm (RESEARCH Pattern 5):
 * 1. combined = [...a, ...b]
 * 2. dedupe by `cid` (first occurrence wins via Set filter)
 * 3. sort by `timestamp` DESC (newest first)
 * 4. `versions` = first `maxVersions` entries; `prunedCids` = remaining cids
 *
 * @param a - First array (or undefined)
 * @param b - Second array (or undefined)
 * @param maxVersions - Maximum number of versions to keep
 * @returns merged versions and pruned cids
 */
export function mergeVersions(
  a: VersionEntry[] | undefined,
  b: VersionEntry[] | undefined,
  maxVersions: number
): { versions: VersionEntry[]; prunedCids: string[] } {
  const combined = [...(a ?? []), ...(b ?? [])];

  // Dedupe by cid — first occurrence wins
  const seen = new Set<string>();
  const deduped = combined.filter((v) => {
    if (seen.has(v.cid)) return false;
    seen.add(v.cid);
    return true;
  });

  // Sort newest first
  deduped.sort((x, y) => y.timestamp - x.timestamp);

  const versions = deduped.slice(0, maxVersions);
  const prunedCids = deduped.slice(maxVersions).map((v) => v.cid);

  return { versions, prunedCids };
}

/**
 * Create a per-file IPNS metadata record.
 *
 * Generates a random Ed25519 IPNS keypair for the file, encrypts file metadata
 * with the parent folder's key, uploads to IPFS, and creates a signed IPNS record.
 *
 * @returns File IPNS name, record payload for batch publish, and ECIES-wrapped IPNS private key
 */
export async function createFileMetadata(params: {
  fileId: string;
  cid: string;
  fileKeyEncrypted: string;
  fileIv: string;
  size: number;
  mimeType: string;
  folderKey: Uint8Array;
  userPublicKey: Uint8Array;
  ctx: SdkContext;
  teeKeys?: TeeKeys;
  encryptionMode?: 'GCM' | 'CTR';
}): Promise<{
  fileMetaIpnsName: string;
  ipnsRecord: FileIpnsRecordPayload;
  ipnsPrivateKeyEncrypted: string;
}> {
  // 1. Generate random Ed25519 IPNS keypair for this file
  const ipnsKeypair = await generateFileIpnsKeypair();

  // All key-using operations inside try/finally to guarantee zeroization
  try {
    // 2. ECIES-wrap the IPNS private key with user's public key for storage in FilePointer
    const wrappedIpnsKey = await wrapKey(ipnsKeypair.privateKey, params.userPublicKey);
    const ipnsPrivateKeyEncrypted = bytesToHex(wrappedIpnsKey);

    const now = Date.now();
    const metadata: FileMetadata = {
      version: 'v1',
      cid: params.cid,
      fileKeyEncrypted: params.fileKeyEncrypted,
      fileIv: params.fileIv,
      size: params.size,
      mimeType: params.mimeType,
      encryptionMode: params.encryptionMode ?? 'GCM',
      createdAt: now,
      modifiedAt: now,
    };

    // 4. Encrypt with parent folderKey
    const encrypted: EncryptedFileMetadata = await encryptFileMetadata(metadata, params.folderKey);

    // 5. Upload encrypted metadata to IPFS
    const jsonStr = JSON.stringify(encrypted);
    const encryptedBytes = new TextEncoder().encode(jsonStr);
    const { cid: metadataCid } = await addToIpfs(params.ctx, encryptedBytes);

    // 6. Create IPNS record (sequence number 1 for new records)
    const record = await createIpnsRecord(
      ipnsKeypair.privateKey,
      `/ipfs/${metadataCid}`,
      1n,
      IPNS_LIFETIME_MS
    );

    // 7. Marshal and base64 encode the record
    const recordBytes = marshalIpnsRecord(record);
    const recordBase64 = uint8ToBase64(recordBytes);

    // 8. TEE enrollment: encrypt IPNS private key with TEE public key
    let teeEncryptedIpnsPrivateKey: string | undefined;
    let keyEpoch: number | undefined;

    if (params.teeKeys?.currentPublicKey) {
      const teePublicKey = hexToBytes(params.teeKeys.currentPublicKey);
      const encryptedKey = await wrapKey(ipnsKeypair.privateKey, teePublicKey);
      teeEncryptedIpnsPrivateKey = bytesToHex(encryptedKey);
      keyEpoch = params.teeKeys.currentEpoch;
    }

    return {
      fileMetaIpnsName: ipnsKeypair.ipnsName,
      ipnsRecord: {
        ipnsName: ipnsKeypair.ipnsName,
        recordBase64,
        publicKey: uint8ToBase64(ipnsKeypair.publicKey),
        metadataCid,
        encryptedIpnsPrivateKey: teeEncryptedIpnsPrivateKey,
        keyEpoch,
      },
      ipnsPrivateKeyEncrypted,
    };
  } finally {
    // Zero the private key on all exit paths (success and failure)
    ipnsKeypair.privateKey.fill(0);
  }
}

/**
 * Resolve a file's per-IPNS metadata record.
 *
 * Resolves the file's IPNS name to get the current metadata CID,
 * fetches the encrypted metadata from IPFS, and decrypts with the
 * parent folder's key.
 *
 * @returns Decrypted file metadata and the resolved metadata CID
 */
export async function resolveFileMetadata(
  fileMetaIpnsName: string,
  folderKey: Uint8Array,
  ctx: SdkContext
): Promise<{ metadata: FileMetadata; metadataCid: string }> {
  const resolved = await resolveIpnsRecord(fileMetaIpnsName, ctx);

  if (!resolved) {
    throw new Error('File metadata IPNS not found');
  }

  const encryptedBytes = await fetchFromIpfs(ctx, resolved.cid);
  const encryptedJson = new TextDecoder().decode(encryptedBytes);
  const encrypted: EncryptedFileMetadata = JSON.parse(encryptedJson);
  const metadata = await decryptFileMetadata(encrypted, folderKey);

  return { metadata, metadataCid: resolved.cid };
}

/**
 * Update an existing file's per-IPNS metadata record.
 *
 * Publishes with CAS (expectedSequenceNumber) to close the TOCTOU window (D-06).
 * On 409 conflict, applies latest-wins semantics by modifiedAt: the winner keeps
 * its content pointer; the loser's content is preserved as a VersionEntry (D-07).
 * versions[] union-merged/deduped/sorted/capped by maxVersionsPerFile (default 10).
 * Throws ConflictError after two total publish attempts.
 *
 * Contract change from original: now publishes internally via createAndPublishIpnsRecord
 * and returns { ipnsName, metadataCid, newSequenceNumber, prunedCids }.
 * The old return shape { ipnsRecord, prunedCids } is replaced. Plan 04 callers
 * (useFileOperations.ts:416, shared-write.ts:450) must be updated to consume this shape.
 *
 * @returns Published IPNS name, CID, sequence number, and pruned version CIDs
 */
export async function updateFileMetadata(params: {
  fileIpnsPrivateKey: Uint8Array;
  fileMetaIpnsName: string;
  folderKey: Uint8Array;
  currentMetadata: FileMetadata;
  updates: Partial<
    Pick<FileMetadata, 'cid' | 'fileKeyEncrypted' | 'fileIv' | 'size' | 'encryptionMode'>
  >;
  createVersion: boolean;
  maxVersionsPerFile?: number;
  ctx: SdkContext;
}): Promise<{
  ipnsName: string;
  metadataCid: string;
  newSequenceNumber: bigint;
  prunedCids: string[];
}> {
  const maxVersions = params.maxVersionsPerFile ?? MAX_VERSIONS_PER_FILE;

  // 1. Build version history for the initial (pre-conflict) metadata
  let versions: VersionEntry[] | undefined;
  let prunedCids: string[] = [];

  if (params.createVersion) {
    const versionEntry: VersionEntry = {
      cid: params.currentMetadata.cid,
      fileKeyEncrypted: params.currentMetadata.fileKeyEncrypted,
      fileIv: params.currentMetadata.fileIv,
      size: params.currentMetadata.size,
      timestamp: Date.now(),
      encryptionMode: params.currentMetadata.encryptionMode ?? 'GCM',
    };
    const allVersions = [versionEntry, ...(params.currentMetadata.versions ?? [])];

    versions = allVersions.slice(0, maxVersions);
    prunedCids = allVersions.slice(maxVersions).map((v) => v.cid);
  } else {
    versions = params.currentMetadata.versions;
  }

  // 2. Merge updates into current metadata
  const updatedMetadata: FileMetadata = {
    ...params.currentMetadata,
    ...params.updates,
    ...(versions && versions.length > 0 ? { versions } : { versions: undefined }),
    modifiedAt: Date.now(),
  };

  // 3. Resolve current IPNS to get sequence number (CAS base)
  const resolved = await resolveIpnsRecord(params.fileMetaIpnsName, params.ctx);
  if (!resolved) {
    throw new Error(
      `Cannot update file metadata: existing IPNS record not found for ${params.fileMetaIpnsName}`
    );
  }
  let currentSeq = resolved.sequenceNumber;

  // 4. Encrypt and upload the initial updated metadata
  let currentCid = await encryptAndUpload(updatedMetadata, params.folderKey, params.ctx);

  // 5. Publish with CAS — on 409 apply latest-wins + loser-becomes-version, then retry once
  try {
    // Attempt 1
    try {
      const result = await createAndPublishIpnsRecord({
        ipnsPrivateKey: params.fileIpnsPrivateKey,
        ipnsName: params.fileMetaIpnsName,
        metadataCid: currentCid,
        sequenceNumber: currentSeq + 1n,
        expectedSequenceNumber: currentSeq.toString(),
        ctx: params.ctx,
      });
      return {
        ipnsName: params.fileMetaIpnsName,
        metadataCid: currentCid,
        newSequenceNumber: result.sequenceNumber,
        prunedCids,
      };
    } catch (err) {
      const is409 =
        (err as Error & { status?: number }).status === 409 ||
        (err as Error & { response?: { status?: number } }).response?.status === 409;

      if (!is409) throw err; // Non-409: propagate unchanged

      // --- Conflict merge ---
      // Re-resolve authoritatively
      const reResolved = await resolveIpnsRecord(params.fileMetaIpnsName, params.ctx);
      if (!reResolved) {
        throw new ConflictError(params.fileMetaIpnsName, 1, currentSeq);
      }
      const lastRemoteSeq = reResolved.sequenceNumber;
      currentSeq = lastRemoteSeq;

      // Fetch and decrypt remote FileMetadata
      const remoteEncryptedBytes = await fetchFromIpfs(params.ctx, reResolved.cid);
      const remoteEncryptedJson = new TextDecoder().decode(remoteEncryptedBytes);
      const remoteEncrypted: EncryptedFileMetadata = JSON.parse(remoteEncryptedJson);
      const remoteMeta = await decryptFileMetadata(remoteEncrypted, params.folderKey);

      // Latest-wins by modifiedAt (>= prefers local on tie)
      const localModifiedAt = updatedMetadata.modifiedAt ?? 0;
      const remoteModifiedAt = remoteMeta.modifiedAt ?? 0;
      const localWins = localModifiedAt >= remoteModifiedAt;

      const winner = localWins ? updatedMetadata : remoteMeta;
      const loser = localWins ? remoteMeta : updatedMetadata;

      // The loser's current content becomes a VersionEntry
      const loserAsVersion: VersionEntry = {
        cid: loser.cid,
        fileKeyEncrypted: loser.fileKeyEncrypted,
        fileIv: loser.fileIv,
        size: loser.size,
        timestamp: loser.modifiedAt ?? Date.now(),
        encryptionMode: (loser.encryptionMode as 'GCM' | 'CTR') ?? 'GCM',
      };

      // Merge: winner's versions + loserAsVersion merged with remote's versions
      const { versions: mergedVersions, prunedCids: extraPruned } = mergeVersions(
        [...(winner.versions ?? []), loserAsVersion],
        remoteMeta.versions,
        maxVersions
      );

      // Build merged metadata
      const mergedMetadata: FileMetadata = {
        ...winner,
        versions: mergedVersions.length > 0 ? mergedVersions : undefined,
        modifiedAt: winner.modifiedAt ?? Date.now(),
      };

      // Filter accumulated prunedCids against the set of CIDs actually referenced by the
      // published mergedMetadata (CR-02 / D-07): a CID resurrected into mergedMetadata.versions
      // by the remote merge must NOT be returned for unpinning.  De-dupe the combined set first
      // to prevent phantom unpin retries from duplicate entries.
      const referenced = new Set([
        mergedMetadata.cid,
        ...(mergedMetadata.versions ?? []).map((v) => v.cid),
      ]);
      prunedCids = [...new Set([...prunedCids, ...extraPruned])].filter((c) => !referenced.has(c));

      // Re-encrypt and re-upload merged metadata
      currentCid = await encryptAndUpload(mergedMetadata, params.folderKey, params.ctx);

      // Attempt 2 (retry)
      try {
        const retryResult = await createAndPublishIpnsRecord({
          ipnsPrivateKey: params.fileIpnsPrivateKey,
          ipnsName: params.fileMetaIpnsName,
          metadataCid: currentCid,
          sequenceNumber: currentSeq + 1n,
          expectedSequenceNumber: currentSeq.toString(),
          ctx: params.ctx,
        });
        return {
          ipnsName: params.fileMetaIpnsName,
          metadataCid: currentCid,
          newSequenceNumber: retryResult.sequenceNumber,
          prunedCids,
        };
      } catch (retryErr) {
        const retryIs409 =
          (retryErr as Error & { status?: number }).status === 409 ||
          (retryErr as Error & { response?: { status?: number } }).response?.status === 409;

        if (retryIs409) {
          throw new ConflictError(params.fileMetaIpnsName, 2, currentSeq);
        }
        throw retryErr;
      }
    }
  } finally {
    // Zeroize the private key on all exit paths (T-44-12 / PATTERNS shared pattern).
    // Caller passes the key buffer; fill(0) zeroes it in-place after publish completes.
    params.fileIpnsPrivateKey.fill(0);
  }
}

/**
 * Helper: encrypt FileMetadata with folderKey and upload to IPFS.
 * Returns the resulting CID.
 */
async function encryptAndUpload(
  metadata: FileMetadata,
  folderKey: Uint8Array,
  ctx: SdkContext
): Promise<string> {
  const encrypted = await encryptFileMetadata(metadata, folderKey);
  const jsonStr = JSON.stringify(encrypted);
  const encryptedBytes = new TextEncoder().encode(jsonStr);
  const { cid } = await addToIpfs(ctx, encryptedBytes);
  return cid;
}
