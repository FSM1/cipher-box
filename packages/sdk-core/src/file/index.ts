/**
 * File Metadata Service — per-file IPNS operations.
 *
 * Phase 62 stub: the entire per-file-IPNS metadata seal path belongs to the write-chain
 * (phase 65). Functions that create, resolve, or update file metadata throw
 * 'not implemented — phase 65 (write-chain file node seal)' until that phase rewires them.
 *
 * The original implementation for FileMetadata (EncryptedFileMetadata / VersionEntry) is
 * preserved in the quarantined test suite (file.test.ts, TODO phase 65) as the spec the
 * owning phase revives.
 *
 * mergeVersions is a pure utility (no IPNS seal); it is kept functional with a local
 * FileVersionEntry type that mirrors the pre-v3 VersionEntry shape until phase 65
 * rewires it to the Node-based version history.
 */

import { createIpnsRecord, marshalIpnsRecord } from '@cipherbox/core';
import { wrapKey, bytesToHex, hexToBytes } from '@cipherbox/crypto';
import type { SdkContext, TeeKeys } from '../types';
import { addToIpfs } from '../ipfs';
import { resolveIpnsRecord } from '../ipns';

/** IPNS record lifetime: 24 hours in milliseconds */
const IPNS_LIFETIME_MS = 24 * 60 * 60 * 1000;

/** Maximum number of past versions retained per file (VER-04) */
const MAX_VERSIONS_PER_FILE = 10;

// Suppress unused import warnings — these will be used by phase 65 rewiring
void createIpnsRecord;
void marshalIpnsRecord;
void wrapKey;
void bytesToHex;
void hexToBytes;
void addToIpfs;
void resolveIpnsRecord;
void IPNS_LIFETIME_MS;
void MAX_VERSIONS_PER_FILE;

/** Safe base64 encoding that avoids call stack overflow from spread operator */
function uint8ToBase64(bytes: Uint8Array): string {
  void bytes;
  throw new Error('not implemented — phase 65 (write-chain file node seal)');
}
void uint8ToBase64;

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
 * @deprecated Phase 65 will replace with Node-based version history (NodeContent.versions).
 * Kept here so mergeVersions typechecks and the quarantined test suite (file.test.ts)
 * revives cleanly in phase 65.
 */
export type FileVersionEntry = {
  cid: string;
  /** ECIES hex-wrapped file key (legacy; phase 65 replaces with sealed-body fileKey) */
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
 * @stub phase 65 — will create a file Node, seal content under a fresh fileReadKey,
 * seal the readKey under the parent folder readKey as a SealedChildRef, and publish
 * the file Node to its IPNS name.
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
  void params;
  throw new Error('not implemented — phase 65 (write-chain file node seal)');
}

/**
 * Resolve a file's per-IPNS metadata record.
 *
 * @stub phase 65 — will resolve the file Node IPNS name, fetch the PublishedNode,
 * and unseal the content under the file readKey.
 */
export async function resolveFileMetadata(
  fileMetaIpnsName: string,
  folderKey: Uint8Array,
  ctx: SdkContext
): Promise<{ metadata: unknown; metadataCid: string }> {
  void fileMetaIpnsName;
  void folderKey;
  void ctx;
  throw new Error('not implemented — phase 65 (write-chain file node seal)');
}

/**
 * Update an existing file's per-IPNS metadata record.
 *
 * @stub phase 65 — will update the file Node content descriptor, re-seal the read-body,
 * and republish the file Node to its IPNS name with CAS.
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
  throw new Error('not implemented — phase 65 (write-chain file node seal)');
}
