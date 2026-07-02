/**
 * File Metadata Service - Per-file Node operations
 *
 * `resolveFileMetadata` is implemented (68.1-04) using the web-native read-chain
 * primitives — `resolveIpnsRecord` (ipns.service, ROT-07 anti-rollback gated) and
 * `fetchFromIpfs` (lib/api/ipfs, ctx-free relay client) — plus `@cipherbox/core`'s
 * `unsealChildReadKey`/`unsealNode` to recover the file's own readKey from its
 * `SealedChildRef` (sealed under the parent folder's readKey) and unseal its
 * `NodeContent`. This mirrors sdk-core's `resolveFileMetadata`
 * (packages/sdk-core/src/file/index.ts, 68.1-07) but sourced through the web's own
 * ctx-less IPNS/IPFS clients (which additionally apply the ROT-07 durable
 * anti-rollback floor sdk-core's raw resolveIpnsRecord does not) rather than the
 * sdk-core ctx-based helpers, since the web app has no `SdkContext` bridge.
 *
 * `createFileMetadata` / `updateFileMetadata` / version-transform helpers remain
 * stubs — file creation and update via the Node write-chain are owned by later
 * plans (68.1-09/68.1-12).
 */

import type { SealedChildRef, VersionEntry, NodeContent, PublishedNode } from '@cipherbox/core';
import { unsealNode, unsealChildReadKey } from '@cipherbox/core';
import { resolveIpnsRecord } from './ipns.service';
import { fetchFromIpfs } from '../lib/api/ipfs';

/** Record payload ready for batch publish */
export type FileIpnsRecordPayload = {
  ipnsName: string;
  recordBase64: string;
  metadataCid: string;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
};

/** Content fields applied as `updates` when routing a file metadata write through the SDK client. */
export type FileContentUpdates = {
  cid?: string;
  fileKeyEncrypted?: string;
  fileIv?: string;
  size?: number;
  encryptionMode?: 'GCM' | 'CTR';
};

/**
 * Create a per-file Node record.
 * @stub phase 65 — requires Node write-chain (NodeWriteBody sealing)
 */
export async function createFileMetadata(_params: {
  fileId: string;
  cid: string;
  fileKeyEncrypted: string;
  fileIv: string;
  size: number;
  mimeType: string;
  folderKey: Uint8Array;
  userPublicKey: Uint8Array;
  encryptionMode?: 'GCM' | 'CTR';
}): Promise<{
  fileMetaIpnsName: string;
  ipnsRecord: FileIpnsRecordPayload;
  ipnsPrivateKeyEncrypted: string;
}> {
  throw new Error('not implemented — phase 65 (file creation requires Node write-chain)');
}

/**
 * Resolve a file Node's content.
 *
 * `fileRef` is the file's `SealedChildRef` as it lives in the parent folder's
 * children (carries `readKeySealed` + `generation`, needed to derive the file's
 * own readKey); `folderKey` is the parent folder's decrypted readKey.
 *
 * Two-step read-chain hop (mirrors `navigateReadChain` / client.ts `dfsFindFolder`
 * generation-source rule — `fileRef.generation` is the PARENT MIRROR, never the
 * file's own envelope generation):
 *   1. Resolve + fetch the file's `PublishedNode` envelope (`kind`/`id` are
 *      plaintext — needed for the child-readkey AAD).
 *   2. `unsealChildReadKey(fileRef.readKeySealed, folderKey, envelope.id, 'file',
 *      fileRef.generation)` recovers the file's own readKey, then `unsealNode`
 *      unseals its `NodeContent`.
 *
 * @security The file readKey recovered here is minted internally by this
 *   function (never returned to the caller) — zeroed on every exit path. The
 *   returned `content.fileKey` is caller-owned and NOT zeroed (D-09), matching
 *   sdk-core's `resolveFileMetadata`.
 */
export async function resolveFileMetadata(
  fileRef: SealedChildRef,
  folderKey: Uint8Array
): Promise<{
  metadata: NodeContent;
  metadataCid: string;
}> {
  const resolved = await resolveIpnsRecord(fileRef.ipnsName, {
    generation: fileRef.generation,
    versionFloor: Number(fileRef.versionFloor),
  });
  if (!resolved) {
    throw new Error(`resolveFileMetadata: IPNS record not found for ${fileRef.ipnsName}`);
  }

  const raw = await fetchFromIpfs(resolved.cid);
  const publishedNode = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;

  let fileReadKey: Uint8Array | null = await unsealChildReadKey(
    fileRef.readKeySealed,
    folderKey,
    publishedNode.id,
    'file',
    fileRef.generation
  );

  try {
    const node = await unsealNode(publishedNode, fileReadKey);
    if (node.kind !== 'file' || !node.content) {
      throw new Error(`resolveFileMetadata: node at ${fileRef.ipnsName} is not a file node`);
    }
    return { metadata: node.content, metadataCid: resolved.cid };
  } finally {
    // fileReadKey is minted internally by this function (recovered from the
    // read-chain, never handed to the caller) — zero it on every exit path.
    fileReadKey.fill(0);
    fileReadKey = null;
  }
}

/**
 * Determine whether a file content update should create a new version entry.
 * @stub phase 65 — version logic moves to NodeContent.versions
 */
export function shouldCreateVersion(
  _currentVersions: VersionEntry[] | undefined,
  _forceVersion: boolean
): boolean {
  throw new Error('not implemented — phase 65 (version check requires NodeContent.versions)');
}

/**
 * Update an existing file Node.
 * @stub phase 65 — requires Node write-chain
 */
export async function updateFileMetadata(_params: {
  fileIpnsPrivateKey: Uint8Array;
  fileMetaIpnsName: string;
  folderKey: Uint8Array;
  updates: FileContentUpdates;
  currentVersions?: VersionEntry[];
  createVersion: boolean;
}): Promise<{
  ipnsRecord: FileIpnsRecordPayload;
  prunedCids: string[];
}> {
  throw new Error('not implemented — phase 65 (file update requires Node write-chain)');
}

/**
 * Compute the metadata transform for restoring a previous version (pure, no publish).
 * @stub phase 65 — requires NodeContent.versions
 */
export function computeRestoreVersionUpdate(
  _versions: VersionEntry[],
  _versionIndex: number
): { updates: FileContentUpdates; retainedVersions: VersionEntry[]; prunedCids: string[] } {
  throw new Error('not implemented — phase 65 (version restore requires NodeContent.versions)');
}

/**
 * Compute the metadata transform for deleting a past version (pure, no publish).
 * @stub phase 65 — requires NodeContent.versions
 */
export function computeDeleteVersionUpdate(
  _versions: VersionEntry[],
  _versionIndex: number
): { retainedVersions: VersionEntry[]; deletedCid: string } {
  throw new Error('not implemented — phase 65 (version delete requires NodeContent.versions)');
}
