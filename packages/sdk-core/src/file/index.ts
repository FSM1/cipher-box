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
 *   - resolveFileMetadata resolves + fetches + unseals a file Node's content (read-only).
 *   - updateFileMetadata rebuilds the file Node in place and republishes it directly
 *     (single-shot, matches shared-write.ts updateSharedFile — no CAS retry/merge; the
 *     legacy CAS+merge behaviour in the quarantined file.test.ts is out of scope here).
 *
 * Security invariants (D-09):
 *   - createFileMetadata mints fileReadKey/fileWriteKey and returns them RAW to the
 *     caller (never zeroed) — the caller becomes the terminal owner (mirrors
 *     createSubfolder). The minted Ed25519 ipnsPrivateKey never leaves this module raw
 *     (only ECIES-wrapped-for-TEE); it is zeroed once consumed, on every exit path.
 *   - Never logs key material (T-62-03).
 */

import { createIpnsRecord, marshalIpnsRecord, sealNode, unsealNode } from '@cipherbox/core';
import type {
  Node,
  NodeContent,
  PublishedNode,
  EncryptionMode,
  VersionEntry,
} from '@cipherbox/core';
import {
  generateRandomBytes,
  generateEd25519Keypair,
  deriveIpnsName,
  decryptAesGcm,
  decryptAesCtr,
  AES_KEY_SIZE,
  AES_IV_SIZE,
  AES_CTR_IV_SIZE,
  hexToBytes,
  bytesToHex,
  bytesToBase64,
  base64ToBytes,
} from '@cipherbox/crypto';
import type { SdkContext, TeeKeys, DownloadProgressCallback } from '../types';
import { addToIpfs, fetchFromIpfs } from '../ipfs';
import { resolveIpnsRecord, createAndPublishIpnsRecord } from '../ipns';
import { wrapIpnsKeyForTee } from '../tee/wrap';

/** IPNS record lifetime: 24 hours in milliseconds */
const IPNS_LIFETIME_MS = 24 * 60 * 60 * 1000;

/** Maximum number of past versions retained per file (VER-04) */
const MAX_VERSIONS_PER_FILE = 10;

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
 * Cap a file's version history at `maxVersions`, folding in one new incoming
 * version entry (the content descriptor just superseded by this update).
 *
 * Delegates dedupe/sort/cap to the existing `mergeVersions` utility by mapping
 * v3 `VersionEntry` (NODE-02: `createdAt` + raw `fileKey`) to the legacy
 * `FileVersionEntry` shape it operates on (`timestamp`), then resolving the
 * returned cids back to their original `VersionEntry` objects via a cid lookup
 * (mergeVersions never transforms elements, so the lookup is exact). This keeps
 * `mergeVersions` itself untouched (D-03: reuse the working utility as-is).
 */
function capVersions(
  existing: VersionEntry[],
  incoming: VersionEntry,
  maxVersions: number
): { versions: VersionEntry[]; prunedCids: string[] } {
  const byCid = new Map<string, VersionEntry>();
  for (const v of existing) byCid.set(v.cid, v);
  byCid.set(incoming.cid, incoming);

  const toLegacy = (v: VersionEntry): FileVersionEntry => ({
    cid: v.cid,
    fileIv: v.fileIv,
    size: v.size,
    timestamp: v.createdAt,
    encryptionMode: v.encryptionMode,
  });

  const { versions: mergedLegacy, prunedCids } = mergeVersions(
    existing.map(toLegacy),
    [toLegacy(incoming)],
    maxVersions
  );

  const versions = mergedLegacy.map((lv) => {
    const original = byCid.get(lv.cid);
    if (!original) {
      throw new Error(`capVersions: no original VersionEntry found for cid ${lv.cid}`);
    }
    return original;
  });

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

  // Validate raw crypto inputs BEFORE minting keys / sealing / publishing. A
  // wrong-length fileKey or fileIv would otherwise be stored verbatim in the
  // sealed NodeContent and only surface (undecryptably) at download time. The
  // internal upload path is covered by encryptAesGcm/Ctr's own length checks, but
  // the external encryptFn (Web Worker) and direct callers are not — fail closed
  // here with a clear crypto error (CLAUDE.md: proper error handling for crypto).
  if (params.fileKey.length !== AES_KEY_SIZE) {
    throw new Error(
      `createFileMetadata: fileKey must be ${AES_KEY_SIZE} bytes (AES-256), got ${params.fileKey.length}`
    );
  }
  const expectedIvLength = mode === 'CTR' ? AES_CTR_IV_SIZE : AES_IV_SIZE;
  if (params.fileIv.length !== expectedIvLength) {
    throw new Error(
      `createFileMetadata: fileIv must be ${expectedIvLength} bytes for ${mode} mode, got ${params.fileIv.length}`
    );
  }

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
      // ECIES-wrap the file IPNS private key under the TEE public key. Do NOT zero
      // fileIpnsPrivateKey here — wrapIpnsKeyForTee borrows the buffer, it does not
      // consume it; the caller is the terminal owner (D-09).
      const teePublicKeyBytes = hexToBytes(currentPublicKey);
      const wrappedBytes = await wrapIpnsKeyForTee(fileIpnsPrivateKey, teePublicKeyBytes);
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
 * Resolves the file IPNS name, fetches the PublishedNode, and unseals the content
 * under the file readKey (read-only — no writeKey needed).
 *
 * @security Does NOT zero fileReadKey — caller is the terminal owner (D-09). The
 *   returned content.fileKey is caller-owned and NOT zeroed here.
 */
export async function resolveFileMetadata(
  fileMetaIpnsName: string,
  fileReadKey: Uint8Array,
  ctx: SdkContext
): Promise<{ metadata: NodeContent; metadataCid: string }> {
  const resolved = await resolveIpnsRecord(fileMetaIpnsName, ctx);
  if (!resolved) {
    throw new Error(`resolveFileMetadata: IPNS record not found for ${fileMetaIpnsName}`);
  }
  const raw = await fetchFromIpfs(ctx, resolved.cid);
  const publishedNode = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
  const node = await unsealNode(publishedNode, fileReadKey);

  if (node.kind !== 'file' || !node.content) {
    throw new Error(`resolveFileMetadata: node at ${fileMetaIpnsName} is not a file node`);
  }

  return { metadata: node.content, metadataCid: resolved.cid };
}

/**
 * Download and decrypt a file's content using its raw (non-ECIES-wrapped) fileKey.
 *
 * Fetches the CID from IPFS and decrypts with the raw fileKey recovered from a
 * resolved NodeContent (D-07/NODE-02 — the v3 model stores fileKey raw inside the
 * sealed read-body, never ECIES-wrapped). `fileIv` is base64 (matches NodeContent.fileIv).
 *
 * @security Does NOT zero fileKey — it is caller-supplied (from a previously resolved
 *   NodeContent); the caller remains the terminal owner (D-09), matching the web
 *   layer's own downloadSharedFile pattern (useSharedNavigationActions.ts).
 */
export async function downloadFileContent(params: {
  cid: string;
  /** Raw 32-byte AES-256 file key (caller-owned — NOT zeroed here) */
  fileKey: Uint8Array;
  /** Base64 IV (matches NodeContent.fileIv) */
  fileIv: string;
  encryptionMode?: EncryptionMode;
  ctx: SdkContext;
  onProgress?: DownloadProgressCallback;
}): Promise<Uint8Array> {
  const ciphertext = await fetchFromIpfs(params.ctx, params.cid, params.onProgress);
  const iv = base64ToBytes(params.fileIv);

  return params.encryptionMode === 'CTR'
    ? decryptAesCtr(ciphertext, params.fileKey, iv)
    : decryptAesGcm(ciphertext, params.fileKey, iv);
}

/** New content fields supplied for a file content update (versions managed internally). */
export type UpdateFileContentParams = {
  cid: string;
  /** Raw 32-byte AES-256 file key for the new content revision */
  fileKey: Uint8Array;
  /** Raw IV bytes used to encrypt the new content (base64-encoded for the wire) */
  fileIv: Uint8Array;
  size: number;
  mimeType: string;
  encryptionMode?: EncryptionMode;
};

/**
 * Update an existing file's per-IPNS metadata record.
 *
 * Rebuilds the file Node preserving id/generation/createdAt, optionally folding the
 * superseded content descriptor into version history (capped at
 * maxVersionsPerFile/MAX_VERSIONS_PER_FILE via `capVersions`), and republishes
 * directly at fileSequenceNumber+1 (single-shot — mirrors
 * packages/sdk/src/share/shared-write.ts updateSharedFile; no CAS retry/merge).
 *
 * @security Does NOT zero fileReadKey, fileWriteKey, or any fileKey embedded in
 *   currentMetadata/updates — all are caller-supplied and the caller remains the
 *   terminal owner (D-09). DOES zero fileIpnsPrivateKey on every exit path
 *   (T-47-01) — this function is its terminal owner (matches every client.ts
 *   call site's doc comment, which already assumed this; T-68.1-12-04 fixed
 *   the prior no-op gap where this docstring said otherwise and no `.fill(0)`
 *   existed).
 */
export async function updateFileMetadata(params: {
  /** Ed25519 seed recovered from the file node's write-body (WRITE-01) */
  fileIpnsPrivateKey: Uint8Array;
  fileReadKey: Uint8Array;
  fileWriteKey: Uint8Array;
  fileMetaIpnsName: string;
  fileSequenceNumber: bigint;
  /** UUID of the file Node — must match WriteChildRef.childId in the parent's write-body */
  nodeId: string;
  /** Current generation of the file Node — preserved verbatim (no rotation on content update) */
  nodeGeneration: number;
  /** Original createdAt of the file Node — preserved verbatim */
  originalCreatedAt: number;
  /** Content descriptor being replaced (folded into version history when createVersion) */
  currentMetadata: NodeContent;
  /** New content fields for this update */
  updates: UpdateFileContentParams;
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
  const now = Date.now();

  try {
    let versions = params.currentMetadata.versions;
    let prunedCids: string[] = [];

    if (params.createVersion) {
      const priorAsVersion: VersionEntry = {
        versionId: crypto.randomUUID(),
        cid: params.currentMetadata.cid,
        fileIv: params.currentMetadata.fileIv,
        size: params.currentMetadata.size,
        createdAt: now,
        encryptionMode: params.currentMetadata.encryptionMode,
        fileKey: params.currentMetadata.fileKey,
      };
      const capped = capVersions(params.currentMetadata.versions, priorAsVersion, maxVersions);
      versions = capped.versions;
      prunedCids = capped.prunedCids;
    }

    const newContent: NodeContent = {
      cid: params.updates.cid,
      fileIv: bytesToBase64(params.updates.fileIv),
      size: params.updates.size,
      mimeType: params.updates.mimeType,
      encryptionMode: params.updates.encryptionMode ?? params.currentMetadata.encryptionMode,
      fileKey: params.updates.fileKey,
      versions,
    };

    const fileNode: Node = {
      schema: 'node/v3',
      kind: 'file',
      id: params.nodeId,
      generation: params.nodeGeneration,
      createdAt: params.originalCreatedAt,
      modifiedAt: now,
      content: newContent,
      writeBody: {
        ipnsPrivateKey: params.fileIpnsPrivateKey,
        writeChildren: [],
      },
    };

    const publishedNode: PublishedNode = await sealNode(
      fileNode,
      params.fileReadKey,
      params.fileWriteKey
    );
    const { cid: metadataCid } = await addToIpfs(
      params.ctx,
      new TextEncoder().encode(JSON.stringify(publishedNode))
    );

    const newSequenceNumber = params.fileSequenceNumber + 1n;
    await createAndPublishIpnsRecord({
      ipnsPrivateKey: params.fileIpnsPrivateKey,
      ipnsName: params.fileMetaIpnsName,
      metadataCid,
      sequenceNumber: newSequenceNumber,
      ctx: params.ctx,
    });

    return {
      ipnsName: params.fileMetaIpnsName,
      metadataCid,
      newSequenceNumber,
      prunedCids,
    };
  } finally {
    // T-47-01: this function is the terminal owner of the caller-supplied
    // fileIpnsPrivateKey once it reaches this call — zero it on every exit
    // path so downstream callers (client.ts replaceFile/restoreFileVersion/
    // deleteFileVersion) do not need to (matches their own doc comments,
    // fixed by T-68.1-12-04 — this `.fill(0)` was previously missing).
    params.fileIpnsPrivateKey.fill(0);
  }
}
