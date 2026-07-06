/**
 * Version Transforms - Pure, no-publish transforms over VersionEntry[]
 *
 * `shouldCreateVersion` / `computeRestoreVersionUpdate` / `computeDeleteVersionUpdate`
 * are pure, no-publish transforms over `NodeContent.versions` (68.1-12) — relocated
 * verbatim from `services/file-metadata.service.ts` (68.2-06, RESEARCH Pitfall 4)
 * ahead of that file's deletion (68.2-11): these three functions are NOT part of the
 * read chain being deleted, only `resolveFileMetadata` is.
 *
 * Ported from the pre-v3 legacy implementation (commit b24e78e90) and adapted to
 * node/v3's raw `Uint8Array` fileKey / base64 fileIv contract (NODE-02).
 */

import type { VersionEntry } from '@cipherbox/core';
import { type UpdateFileContentParams } from '@cipherbox/sdk-core';
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
