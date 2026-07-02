/**
 * File Metadata Service — per-file Node IPNS operations (Phase 68.1-07).
 *
 * Implements the owned per-file Node IPNS chain: create/resolve/update primitives
 * for the v3 node/v3 codec (NODE-02: raw fileKey lives inside the sealed read-body,
 * base64 iv, mandatory encryptionMode). Copied in spirit from
 * packages/sdk/src/share/shared-write.ts (uploadToSharedFolder / updateSharedFile)
 * but using sdk-core's own seams (addToIpfs, fetchFromIpfs, resolveIpnsRecord,
 * createAndPublishIpnsRecord) instead of shared-write's injected callbacks.
 *
 * Design:
 *   - createFileMetadata mints fresh fileReadKey/fileWriteKey/Ed25519 keypair, seals a
 *     new file Node, uploads it, and builds (but does NOT publish) the file's IPNS
 *     record — the caller batch-publishes it (matches the pre-existing UploadResult
 *     contract: client.ts already calls `batchPublishIpnsRecords([uploadResult.ipnsRecord])`).
 *   - resolveFileMetadata / updateFileMetadata: implemented in 68.1-07 Tasks 2/3.
 *
 * Security invariants (D-09):
 *   - createFileMetadata mints fileReadKey/fileWriteKey and returns them RAW to the
 *     caller (never zeroed) — the caller becomes the terminal owner (mirrors
 *     createSubfolder). The minted Ed25519 ipnsPrivateKey never leaves this module raw
 *     (only ECIES-wrapped-for-TEE); it is zeroed once consumed, on every exit path.
 *   - Never logs key material (T-62-03).
 */

import { createIpnsRecord, marshalIpnsRecord, sealNode } from '@cipherbox/core';
import type { Node, NodeContent, PublishedNode, EncryptionMode } from '@cipherbox/core';
import {
  generateRandomBytes,
  generateEd25519Keypair,
  deriveIpnsName,
  wrapKey,
  bytesToHex,
  hexToBytes,
} from '@cipherbox/crypto';
import type { SdkContext, TeeKeys } from '../types';
import { addToIpfs } from '../ipfs';
import { resolveIpnsRecord } from '../ipns';

/** IPNS record lifetime: 24 hours in milliseconds */
const IPNS_LIFETIME_MS = 24 * 60 * 60 * 1000;

/** Maximum number of past versions retained per file (VER-04) */
const MAX_VERSIONS_PER_FILE = 10;

// Suppress unused import/const warnings — consumed by Tasks 2/3 (resolveFileMetadata /
// updateFileMetadata) implemented later in this plan.
void resolveIpnsRecord;
void MAX_VERSIONS_PER_FILE;

// ---------------------------------------------------------------------------
// Base64 helpers (safe — avoid call-stack overflow from spread operator, MEDIUM-08)
// ---------------------------------------------------------------------------

function bytesToBase64(bytes: Uint8Array): string {
  const CHUNK_SIZE = 32768;
  let result = '';
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.length));
    result += String.fromCharCode(...chunk);
  }
  return btoa(result);
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
 * Legacy per-file version entry shape (pre-node/v3).
 *
 * @deprecated Kept only so the pure `mergeVersions` utility typechecks and the
 * quarantined legacy test suite (file.test.ts) revives cleanly if ever needed.
 * The v3 model's version history type is `@cipherbox/core`'s `VersionEntry`
 * (raw fileKey inside the sealed body, mandatory encryptionMode) — see 68.1-07
 * Task 3 (`capVersions`) for the adapter between the two shapes.
 */
export type FileVersionEntry = {
  cid: string;
  /** ECIES hex-wrapped file key (legacy; v3 uses a sealed-body raw fileKey instead) */
  fileKeyEncrypted?: string;
  fileIv: string;
  size: number;
  timestamp: number;
  encryptionMode?: 'GCM' | 'CTR';
};

/**
 * Merge two FileVersionEntry arrays into a single deduped, sorted, capped result.
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
  a: FileVersionEntry[] | undefined,
  b: FileVersionEntry[] | undefined,
  maxVersions: number
): { versions: FileVersionEntry[]; prunedCids: string[] } {
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
 * Mints fileReadKey/fileWriteKey/Ed25519 keypair, builds a NodeContent { cid, fileIv
 * (base64), size, mimeType, encryptionMode, fileKey (raw), versions:[] }, builds a file
 * Node (kind:'file', generation:0, writeBody:{ ipnsPrivateKey, writeChildren:[] }),
 * seals under the minted keys, and uploads to IPFS. Builds — but does NOT publish over
 * the network — the file's first IPNS record (sequenceNumber 1n, strict gate); the
 * caller batch-publishes it via `batchPublishIpnsRecords` (mirrors the pre-existing
 * UploadResult.ipnsRecord contract already wired in client.ts).
 *
 * @security Returns fileReadKey/fileWriteKey RAW to the caller (never zeroed — caller
 *   is the terminal owner, D-09, mirrors createSubfolder). The minted Ed25519
 *   ipnsPrivateKey never leaves this function raw; it is zeroed once consumed
 *   (after sealing + optional TEE-wrap + record signing) on every exit path.
 */
export async function createFileMetadata(params: {
  /** Pre-uploaded IPFS CID of the encrypted content */
  cid: string;
  /** Raw 32-byte AES-256 file key (stored inside the sealed content, D-07/NODE-02) */
  fileKey: Uint8Array;
  /** Raw IV bytes used to encrypt the content (base64-encoded for the wire) */
  fileIv: Uint8Array;
  /** Plaintext size in bytes */
  size: number;
  mimeType: string;
  encryptionMode?: EncryptionMode;
  ctx: SdkContext;
  teeKeys?: TeeKeys;
  /** Optional pre-generated node id (UUID); a fresh UUID is minted when omitted. */
  fileId?: string;
}): Promise<{
  fileMetaIpnsName: string;
  fileNodeId: string;
  fileReadKey: Uint8Array;
  fileWriteKey: Uint8Array;
  ipnsRecord: FileIpnsRecordPayload;
  ipnsPrivateKeyEncrypted?: string;
}> {
  const mode: EncryptionMode = params.encryptionMode ?? 'GCM';

  // Mint fresh keys for this file node — the read/write keys are RETURNED raw to
  // the caller (terminal owner, D-09). Only the Ed25519 private key is fully
  // internal to this function and gets zeroed once consumed.
  const fileReadKey = generateRandomBytes(32);
  const fileWriteKey = generateRandomBytes(32);
  const fileKeypair = generateEd25519Keypair();
  let fileIpnsPrivateKey: Uint8Array | null = fileKeypair.privateKey;

  try {
    const fileIpnsName = await deriveIpnsName(fileKeypair.publicKey);
    const fileNodeId = params.fileId ?? crypto.randomUUID();
    const now = Date.now();

    const nodeContent: NodeContent = {
      cid: params.cid,
      fileIv: bytesToBase64(params.fileIv),
      size: params.size,
      mimeType: params.mimeType,
      encryptionMode: mode,
      fileKey: params.fileKey,
      versions: [],
    };

    const fileNode: Node = {
      schema: 'node/v3',
      kind: 'file',
      id: fileNodeId,
      generation: 0,
      createdAt: now,
      modifiedAt: now,
      content: nodeContent,
      writeBody: {
        ipnsPrivateKey: fileIpnsPrivateKey,
        writeChildren: [],
      },
    };

    const publishedNode: PublishedNode = await sealNode(fileNode, fileReadKey, fileWriteKey);
    const { cid: metadataCid } = await addToIpfs(
      params.ctx,
      new TextEncoder().encode(JSON.stringify(publishedNode))
    );

    // TEE enrollment — mirrors createSubfolder's fail-closed gate (registration.ts).
    let encryptedIpnsPrivateKey: string | undefined;
    let keyEpoch: number | undefined;
    if (params.teeKeys) {
      const { currentPublicKey, currentEpoch } = params.teeKeys;
      if (!currentPublicKey) {
        throw new Error(
          'createFileMetadata: teeKeys.currentPublicKey is missing or empty — refusing to publish un-enrolled file'
        );
      }
      if (!Number.isInteger(currentEpoch) || currentEpoch < 1) {
        throw new Error(
          'createFileMetadata: teeKeys.currentEpoch must be a positive integer (>= 1) — refusing to publish un-enrolled file'
        );
      }
      const teePublicKeyBytes = hexToBytes(currentPublicKey);
      const wrappedBytes = await wrapKey(fileIpnsPrivateKey, teePublicKeyBytes);
      encryptedIpnsPrivateKey = bytesToHex(wrappedBytes);
      keyEpoch = currentEpoch;
    }

    // Build the IPNS record locally (create + sign + marshal) WITHOUT publishing over
    // the network — the caller batch-publishes it (registration.ts addFileToFolder /
    // addFilesToFolder, or standalone via batchPublishIpnsRecords). First publish MUST
    // embed sequenceNumber 1n (Phase-60 strict gate, T-68.1-07-03).
    const record = await createIpnsRecord(
      fileIpnsPrivateKey,
      `/ipfs/${metadataCid}`,
      1n,
      IPNS_LIFETIME_MS
    );
    const recordBase64 = bytesToBase64(marshalIpnsRecord(record));
    const publicKeyBase64 = bytesToBase64(fileKeypair.publicKey);

    const ipnsRecord: FileIpnsRecordPayload = {
      ipnsName: fileIpnsName,
      recordBase64,
      publicKey: publicKeyBase64,
      metadataCid,
      encryptedIpnsPrivateKey,
      keyEpoch,
    };

    // The raw Ed25519 private key never leaves this function (it lives sealed inside
    // the write-body and, when TEE-enrolled, ECIES-wrapped in ipnsRecord). Zero it
    // once consumed (D-09 — this function is its terminal owner).
    fileIpnsPrivateKey.fill(0);
    fileIpnsPrivateKey = null;

    return {
      fileMetaIpnsName: fileIpnsName,
      fileNodeId,
      fileReadKey,
      fileWriteKey,
      ipnsRecord,
      ipnsPrivateKeyEncrypted: encryptedIpnsPrivateKey,
    };
  } catch (err) {
    // fileReadKey/fileWriteKey never reached the caller on this path — zero them.
    // fileIpnsPrivateKey may already be null (nulled after success above) — guard.
    fileReadKey.fill(0);
    fileWriteKey.fill(0);
    fileIpnsPrivateKey?.fill(0);
    throw err;
  }
}

/**
 * Resolve a file's per-IPNS metadata record.
 *
 * @stub 68.1-07 Task 2 — will resolve the file Node IPNS name, fetch the
 * PublishedNode, and unseal the content under the file readKey.
 */
export async function resolveFileMetadata(
  fileMetaIpnsName: string,
  folderKey: Uint8Array,
  ctx: SdkContext
): Promise<{ metadata: unknown; metadataCid: string }> {
  void fileMetaIpnsName;
  void folderKey;
  void ctx;
  throw new Error('not implemented — 68.1-07 Task 2 (write-chain file node seal)');
}

/**
 * Update an existing file's per-IPNS metadata record.
 *
 * @stub 68.1-07 Task 3 — will update the file Node content descriptor, optionally
 * fold the superseded descriptor into version history, and republish the file Node.
 */
export async function updateFileMetadata(params: {
  fileIpnsPrivateKey: Uint8Array;
  fileMetaIpnsName: string;
  folderKey: Uint8Array;
  currentMetadata: unknown;
  updates: unknown;
  createVersion: boolean;
  maxVersionsPerFile?: number;
  ctx: SdkContext;
}): Promise<{
  ipnsName: string;
  metadataCid: string;
  newSequenceNumber: bigint;
  prunedCids: string[];
}> {
  void params;
  throw new Error('not implemented — 68.1-07 Task 3 (write-chain file node seal)');
}
