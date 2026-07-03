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
 * `shouldCreateVersion` / `computeRestoreVersionUpdate` / `computeDeleteVersionUpdate`
 * are pure, no-publish transforms over `NodeContent.versions` (68.1-12) — ported from
 * the pre-v3 legacy implementation (commit b24e78e90) and adapted to node/v3's raw
 * `Uint8Array` fileKey / base64 fileIv contract (NODE-02).
 */

import type { SealedChildRef, VersionEntry, NodeContent, PublishedNode } from '@cipherbox/core';
import { unsealNode, unsealChildReadKey } from '@cipherbox/core';
import { type UpdateFileContentParams } from '@cipherbox/sdk-core';
import { resolveIpnsRecord } from './ipns.service';
import { fetchFromIpfs } from '../lib/api/ipfs';
import { useVaultSettingsStore } from '../stores/vault-settings.store';

/** Content fields applied as `updates` when routing a file metadata write through the SDK client. */
export type FileContentUpdates = UpdateFileContentParams;

/** Decodes a base64 string to a Uint8Array (VersionEntry.fileIv is base64, v3 contract). */
function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
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
 *
 * Ported from the pre-v3 policy (commit b24e78e90), adapted to `VersionEntry`'s
 * `createdAt` field (NODE-02):
 * - `forceVersion` (explicit re-upload, e.g. `ReplaceFileDialog`) always versions.
 * - No existing versions → always version (first version always created).
 * - Otherwise version only if the newest entry is older than the user-configurable
 *   cooldown (`vault-settings.store`'s `versionCooldownMinutes`).
 *
 * @param currentVersions - Current file's version history (may be empty/undefined)
 * @param forceVersion - Whether to force version creation regardless of cooldown
 */
export function shouldCreateVersion(
  currentVersions: VersionEntry[] | undefined,
  forceVersion: boolean
): boolean {
  if (forceVersion) return true;
  if (!currentVersions || currentVersions.length === 0) return true;

  const cooldownMs = useVaultSettingsStore.getState().settings.versionCooldownMinutes * 60 * 1000;
  const newestCreatedAt = currentVersions[0].createdAt;
  return Date.now() - newestCreatedAt >= cooldownMs;
}

/**
 * Compute the metadata transform for restoring a previous version (pure, no publish).
 *
 * Picks `versions[versionIndex]` as the new live content (`updates`, decoding its
 * base64 `fileIv` back to raw bytes for `UpdateFileContentParams`) and removes it
 * from the retained history (`retainedVersions`) so it is not duplicated once the
 * caller republishes. The caller is expected to pass `createVersion: true` to
 * `client.restoreFileVersion` so sdk-core's `updateFileMetadata` folds the
 * pre-restore live content into `retainedVersions` itself (capped, pruning as
 * needed) — this function never needs to compute that fold or cap directly, since
 * it only has `versions`, not the live content descriptor.
 *
 * @param versions - Current file's version history
 * @param versionIndex - Index of the version to restore (0 = newest past version)
 */
export function computeRestoreVersionUpdate(
  versions: VersionEntry[],
  versionIndex: number
): {
  updates: Omit<FileContentUpdates, 'mimeType'>;
  retainedVersions: VersionEntry[];
  prunedCids: string[];
} {
  if (versionIndex < 0 || versionIndex >= versions.length) {
    throw new Error('Invalid version index');
  }

  const versionToRestore = versions[versionIndex];
  const retainedVersions = versions.filter((_, i) => i !== versionIndex);

  return {
    updates: {
      cid: versionToRestore.cid,
      fileKey: versionToRestore.fileKey,
      fileIv: base64ToBytes(versionToRestore.fileIv),
      size: versionToRestore.size,
      encryptionMode: versionToRestore.encryptionMode,
    },
    retainedVersions,
    prunedCids: [],
  };
}

/**
 * Compute the metadata transform for deleting a past version (pure, no publish).
 *
 * Removes the version at `versionIndex` from the history. The live content is
 * untouched — the caller publishes the same content with a pruned version list
 * (`createVersion: false`).
 *
 * @param versions - Current file's version history
 * @param versionIndex - Index of the version to delete
 */
export function computeDeleteVersionUpdate(
  versions: VersionEntry[],
  versionIndex: number
): { retainedVersions: VersionEntry[]; deletedCid: string } {
  if (versionIndex < 0 || versionIndex >= versions.length) {
    throw new Error('Invalid version index');
  }

  const deletedCid = versions[versionIndex].cid;
  const retainedVersions = versions.filter((_, i) => i !== versionIndex);

  return { retainedVersions, deletedCid };
}
