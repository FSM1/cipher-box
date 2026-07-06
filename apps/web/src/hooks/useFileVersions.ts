import { useState, useCallback } from 'react';
import type { FolderOperationState } from './folder-helpers';
import { getRootFolderState } from './folder-helpers';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useQuotaStore } from '../stores/quota.store';
import { useVaultSettingsStore } from '../stores/vault-settings.store';
import { getSdkClient } from '../lib/sdk-provider';
import { computeRestoreVersionUpdate, computeDeleteVersionUpdate } from '../lib/version-transforms';
import { logger } from '../lib/logger';

/** Decodes a base64 string to a Uint8Array (NodeContent.fileIv is base64, v3 contract). */
function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

function resolveParentFolder(parentId: string) {
  const folders = useFolderStore.getState().folders;
  return parentId === 'root'
    ? getRootFolderState(useVaultStore.getState(), folders)
    : folders[parentId];
}

/**
 * React hook for file version management operations (restore, delete).
 *
 * Both handlers (68.1-12) resolve the current `NodeContent` via the read-chain
 * (`client.resolveFileMetadata`, 68.2-11 SDK facade), compute the pure version transform
 * (`computeRestoreVersionUpdate`/`computeDeleteVersionUpdate`, 68.1-12), resolve
 * the file's write-chain signing key via `client.resolveFileIpnsPrivateKey`
 * (T-68.1-12-04), and publish via `client.restoreFileVersion`/`deleteFileVersion`
 * (68.1-09) — unpinning any pruned/deleted CIDs afterward.
 *
 * Returns loading/error state and operation callbacks.
 */
export function useFileVersions() {
  const [state, setState] = useState<FolderOperationState>({
    isLoading: false,
    error: null,
  });

  /**
   * Restore a previous version of a file.
   *
   * The pre-restore live content becomes a new version entry (non-destructive) —
   * `createVersion: true` is passed to `client.restoreFileVersion` so sdk-core's
   * `updateFileMetadata` folds it into `retainedVersions` itself (capped/pruned).
   *
   * @param parentId - Parent folder ID ('root' or folder UUID)
   * @param fileId - IPNS name of the file (`SealedChildRef.ipnsName`)
   * @param versionIndex - Index of the version to restore (0 = newest past version)
   */
  const handleRestoreVersion = useCallback(
    async (parentId: string, fileId: string, versionIndex: number): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const parentFolder = resolveParentFolder(parentId);
        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        // Raw identity (readKeySealed/generation/versionFloor) is needed to
        // unseal the file's read-chain -- the store's display `children`
        // (ResolvedChild[], Plan 09) no longer carries these; `rawChildren`
        // is the same-session write-path mirror (D-09).
        const fileRef = (parentFolder.rawChildren ?? []).find((c) => c.ipnsName === fileId);
        if (!fileRef) {
          throw new Error('File not found in folder');
        }

        const client = getSdkClient();
        const { metadata: currentMetadata } = await client.resolveFileMetadata(
          fileRef,
          parentFolder.folderKey
        );

        const {
          updates,
          retainedVersions,
          prunedCids: computedPrunedCids,
        } = computeRestoreVersionUpdate(currentMetadata.versions, versionIndex);

        // T-68.1-12-04: the write-chain walk lives only inside CipherBoxClient
        // (D-03). Do NOT zero it here — sdk-core updateFileMetadata is its
        // terminal owner (T-47-01).
        const fileIpnsPrivateKey = await client.resolveFileIpnsPrivateKey(
          parentFolder.ipnsName,
          fileId
        );

        const { prunedCids: mergePrunedCids } = await client.restoreFileVersion(
          parentFolder.ipnsName,
          fileId,
          versionIndex,
          {
            fileIpnsPrivateKey,
            currentMetadata: { ...currentMetadata, versions: retainedVersions },
            updates: { ...updates, mimeType: currentMetadata.mimeType },
            createVersion: true,
            maxVersionsPerFile: useVaultSettingsStore.getState().settings.maxVersionsPerFile,
          }
        );

        for (const prunedCid of new Set([...computedPrunedCids, ...mergePrunedCids])) {
          client
            .unpin(prunedCid)
            .catch((err) => logger.warn('[Versions] Unpin pruned CID failed:', err));
        }

        useQuotaStore.getState().fetchQuota();

        setState({ isLoading: false, error: null });
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to restore version';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  /**
   * Delete a specific past version from a file's version history.
   *
   * The live content is untouched — `createVersion` is always `false` on the
   * client call (a version-history edit never folds a new version).
   *
   * @param parentId - Parent folder ID ('root' or folder UUID)
   * @param fileId - IPNS name of the file (`SealedChildRef.ipnsName`)
   * @param versionIndex - Index of the version to delete
   */
  const handleDeleteVersion = useCallback(
    async (parentId: string, fileId: string, versionIndex: number): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const parentFolder = resolveParentFolder(parentId);
        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        // Raw identity (readKeySealed/generation/versionFloor) is needed to
        // unseal the file's read-chain -- the store's display `children`
        // (ResolvedChild[], Plan 09) no longer carries these; `rawChildren`
        // is the same-session write-path mirror (D-09).
        const fileRef = (parentFolder.rawChildren ?? []).find((c) => c.ipnsName === fileId);
        if (!fileRef) {
          throw new Error('File not found in folder');
        }

        const client = getSdkClient();
        const { metadata: currentMetadata } = await client.resolveFileMetadata(
          fileRef,
          parentFolder.folderKey
        );

        const { retainedVersions, deletedCid } = computeDeleteVersionUpdate(
          currentMetadata.versions,
          versionIndex
        );

        // T-68.1-12-04: the write-chain walk lives only inside CipherBoxClient
        // (D-03). Do NOT zero it here — sdk-core updateFileMetadata is its
        // terminal owner (T-47-01).
        const fileIpnsPrivateKey = await client.resolveFileIpnsPrivateKey(
          parentFolder.ipnsName,
          fileId
        );

        const { deletedCid: publishedDeletedCid, prunedCids } = await client.deleteFileVersion(
          parentFolder.ipnsName,
          fileId,
          versionIndex,
          {
            fileIpnsPrivateKey,
            currentMetadata: { ...currentMetadata, versions: retainedVersions },
            updates: {
              cid: currentMetadata.cid,
              fileKey: currentMetadata.fileKey,
              fileIv: base64ToBytes(currentMetadata.fileIv),
              size: currentMetadata.size,
              mimeType: currentMetadata.mimeType,
              encryptionMode: currentMetadata.encryptionMode,
            },
            deletedCid,
            maxVersionsPerFile: useVaultSettingsStore.getState().settings.maxVersionsPerFile,
          }
        );

        const allPrunedCids = [
          ...(publishedDeletedCid ? [publishedDeletedCid] : []),
          ...prunedCids,
        ];
        for (const cid of new Set(allPrunedCids)) {
          client.unpin(cid).catch((err) => logger.warn('[Versions] Unpin pruned CID failed:', err));
        }

        useQuotaStore.getState().fetchQuota();

        setState({ isLoading: false, error: null });
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to delete version';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  return {
    ...state,
    restoreVersion: handleRestoreVersion,
    deleteVersion: handleDeleteVersion,
  };
}
