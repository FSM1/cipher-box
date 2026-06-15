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
import { resolveIpnsRecord } from '../ipns';
import { publishWithCas } from '../cas';

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

  const metadata = await fetchAndDecryptFileMetadata(resolved.cid, folderKey, ctx);

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

  // 3. Resolve the current IPNS record once up front to establish the CAS base
  //    sequence number (publishWithCas re-resolves authoritatively on each 409).
  const resolved = await resolveIpnsRecord(params.fileMetaIpnsName, params.ctx);
  if (!resolved) {
    throw new Error(
      `Cannot update file metadata: existing IPNS record not found for ${params.fileMetaIpnsName}`
    );
  }

  // 4. Publish with CAS — on 409 apply latest-wins + loser-becomes-version (D-07).
  //    The publishWithCas engine owns the resolve→merge→retry skeleton; the
  //    domain-specific encode/decode/merge are injected as callbacks. The
  //    fileIpnsPrivateKey is zeroed in the finally on ALL exit paths (T-47-01).
  try {
    const result = await publishWithCas<FileMetadata>({
      ipnsName: params.fileMetaIpnsName,
      ipnsPrivateKey: params.fileIpnsPrivateKey,
      sequenceNumber: resolved.sequenceNumber,
      ctx: params.ctx,
      maxAttempts: 4,
      backoff: true,
      encodeAndUpload: (metadata) => encryptAndUpload(metadata, params.folderKey, params.ctx),
      decodeRemote: (cid) => fetchAndDecryptFileMetadata(cid, params.folderKey, params.ctx),
      // Latest-wins three-way merge. `base` is unused for files (latest-wins, not
      // structural merge); `local` is the writer's metadata, `remote` is the
      // conflicting authoritative metadata.
      merge: (_base, local, remote) => {
        // Latest-wins by modifiedAt (>= prefers local on tie)
        const localModifiedAt = local.modifiedAt ?? 0;
        const remoteModifiedAt = remote.modifiedAt ?? 0;
        const localWins = localModifiedAt >= remoteModifiedAt;

        const winner = localWins ? local : remote;
        const loser = localWins ? remote : local;

        // The loser's current content becomes a VersionEntry
        const loserAsVersion: VersionEntry = {
          cid: loser.cid,
          fileKeyEncrypted: loser.fileKeyEncrypted,
          fileIv: loser.fileIv,
          size: loser.size,
          timestamp: loser.modifiedAt ?? Date.now(),
          encryptionMode: (loser.encryptionMode as 'GCM' | 'CTR') ?? 'GCM',
        };

        // Merge: winner's versions + loserAsVersion merged with the loser's version
        // history. The second arg MUST be loser.versions, not remote.versions: when the
        // remote wins (localWins === false) the loser is the LOCAL metadata, so passing
        // remote.versions would silently drop the local writer's prior version history.
        const { versions: mergedVersions, prunedCids: extraPruned } = mergeVersions(
          [...(winner.versions ?? []), loserAsVersion],
          loser.versions,
          maxVersions
        );

        const mergedMetadata: FileMetadata = {
          ...winner,
          versions: mergedVersions.length > 0 ? mergedVersions : undefined,
          modifiedAt: winner.modifiedAt ?? Date.now(),
        };

        // CR-02 / D-07: a CID resurrected into mergedMetadata.versions by the remote
        // merge must NOT be returned for unpinning. Filter extraPruned against the set
        // of CIDs actually referenced by the published mergedMetadata. publishWithCas
        // de-dupes the accumulated prunedCids across attempts; this callback only filters
        // the CIDs it produces this round.
        const referenced = new Set([
          mergedMetadata.cid,
          ...(mergedMetadata.versions ?? []).map((v) => v.cid),
        ]);
        const filteredPruned = extraPruned.filter((c) => !referenced.has(c));

        return { merged: mergedMetadata, prunedCids: filteredPruned };
      },
      localData: updatedMetadata,
    });

    // Combine the pre-conflict prunedCids (from the initial version-history cap) with
    // any pruned during conflict merges, then strip CIDs the final published metadata
    // still references (CR-02): the initial prune may include a CID that a remote merge
    // resurrected into versions.
    const finalReferenced = new Set([
      result.publishedData.cid,
      ...(result.publishedData.versions ?? []).map((v) => v.cid),
    ]);
    const combinedPruned = [...new Set([...prunedCids, ...result.prunedCids])].filter(
      (c) => !finalReferenced.has(c)
    );

    return {
      ipnsName: params.fileMetaIpnsName,
      metadataCid: result.cid,
      newSequenceNumber: result.newSequenceNumber,
      prunedCids: combinedPruned,
    };
  } finally {
    // Zeroize the private key on all exit paths (T-47-01 / T-44-12). publishWithCas
    // never zeroes keys; the caller (this function) owns zeroing.
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

/**
 * Helper: fetch encrypted FileMetadata from IPFS by CID and decrypt with folderKey.
 * The read-half companion to encryptAndUpload (mirrors folder's fetchAndDecryptMetadata).
 */
async function fetchAndDecryptFileMetadata(
  cid: string,
  folderKey: Uint8Array,
  ctx: SdkContext
): Promise<FileMetadata> {
  const encryptedBytes = await fetchFromIpfs(ctx, cid);
  const encryptedJson = new TextDecoder().decode(encryptedBytes);
  const encrypted: EncryptedFileMetadata = JSON.parse(encryptedJson);
  return decryptFileMetadata(encrypted, folderKey);
}
