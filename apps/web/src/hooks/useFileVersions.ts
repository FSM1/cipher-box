import { useState, useCallback } from 'react';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useAuthStore } from '../stores/auth.store';
import { useQuotaStore } from '../stores/quota.store';
import { useVaultSettingsStore } from '../stores/vault-settings.store';
import { unpinFromIpfs } from '../lib/api/ipfs';
import { getSdkClient } from '../lib/sdk-provider';
import {
  resolveFileMetadata,
  computeRestoreVersionUpdate,
  computeDeleteVersionUpdate,
  getFileIpnsPrivateKey,
} from '../services/file-metadata.service';
import type { FilePointer } from '@cipherbox/core';
import { getRootFolderState } from './folder-helpers';
import type { FolderOperationState } from './folder-helpers';
import { logger } from '../lib/logger';

/**
 * React hook for file version management operations (restore, delete).
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
   * Swaps the current content with a past version. The current content becomes
   * a new version entry (non-destructive). Publishes updated IPNS record and
   * unpins any pruned version CIDs.
   *
   * @param parentId - Parent folder ID ('root' or folder UUID)
   * @param fileId - File ID (UUID)
   * @param versionIndex - Index of version to restore (0 = newest past version)
   */
  const handleRestoreVersion = useCallback(
    async (parentId: string, fileId: string, versionIndex: number): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const folders = useFolderStore.getState().folders;
        const vault = useVaultStore.getState();
        const auth = useAuthStore.getState();

        if (!auth.vaultKeypair) {
          throw new Error('No ECIES keypair available - please log in again');
        }

        // Get parent folder state
        const parentFolder =
          parentId === 'root' ? getRootFolderState(vault, folders) : folders[parentId];

        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        // Find the FilePointer
        const filePointer = parentFolder.children.find(
          (c) => c.type === 'file' && c.id === fileId
        ) as FilePointer | undefined;

        if (!filePointer) {
          throw new Error('File not found in folder');
        }

        // Resolve current file metadata from IPNS
        const { metadata: currentMetadata } = await resolveFileMetadata(
          filePointer.fileMetaIpnsName,
          parentFolder.folderKey
        );

        // Decrypt the file IPNS private key from FilePointer (or HKDF fallback)
        const { privateKey: fileIpnsPrivateKey, migratedIpnsPrivateKeyEncrypted } =
          await getFileIpnsPrivateKey(
            filePointer,
            auth.vaultKeypair.privateKey,
            auth.vaultKeypair.publicKey
          );

        // Compute the restore transform in the web tier (pure, no publish). The
        // transformed currentMetadata carries the post-restore versions array; updates
        // carries the restored content fields. Routed through the SDK client so the
        // folderTree stays authoritative.
        const {
          currentMetadata: restoredMetadata,
          updates,
          prunedCids,
        } = computeRestoreVersionUpdate(currentMetadata, versionIndex);

        try {
          // client.restoreFileVersion owns the file IPNS publish (CAS internally), the
          // conditional folder publish for lazy IPNS-key migration, folderTree
          // bookkeeping, and the folder:updated emission. The store's
          // children/sequenceNumber are written ONLY by the folder:updated subscription —
          // no direct store writes here. fileIpnsPrivateKey is zeroed in this finally
          // (T-47-01); sdk-core updateFileMetadata also zeroes its own copy.
          await getSdkClient().restoreFileVersion(parentFolder.ipnsName, fileId, versionIndex, {
            fileIpnsPrivateKey,
            currentMetadata: restoredMetadata,
            updates,
            createVersion: false,
            maxVersionsPerFile: useVaultSettingsStore.getState().settings.maxVersionsPerFile,
            ...(migratedIpnsPrivateKeyEncrypted ? { migratedIpnsPrivateKeyEncrypted } : {}),
          });
        } finally {
          fileIpnsPrivateKey.fill(0);
        }

        // Unpin pruned version CIDs
        for (const prunedCid of prunedCids) {
          unpinFromIpfs(prunedCid).catch((err) =>
            logger.warn('[Versions] Unpin pruned CID failed:', err)
          );
        }

        // Refresh quota
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
   * Removes the version from metadata, publishes updated IPNS record, and
   * unpins the deleted version's CID.
   *
   * @param parentId - Parent folder ID ('root' or folder UUID)
   * @param fileId - File ID (UUID)
   * @param versionIndex - Index of version to delete (0 = newest past version)
   */
  const handleDeleteVersion = useCallback(
    async (parentId: string, fileId: string, versionIndex: number): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const folders = useFolderStore.getState().folders;
        const vault = useVaultStore.getState();
        const auth = useAuthStore.getState();

        if (!auth.vaultKeypair) {
          throw new Error('No ECIES keypair available - please log in again');
        }

        // Get parent folder state
        const parentFolder =
          parentId === 'root' ? getRootFolderState(vault, folders) : folders[parentId];

        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        // Find the FilePointer
        const filePointer = parentFolder.children.find(
          (c) => c.type === 'file' && c.id === fileId
        ) as FilePointer | undefined;

        if (!filePointer) {
          throw new Error('File not found in folder');
        }

        // Resolve current file metadata from IPNS
        const { metadata: currentMetadata } = await resolveFileMetadata(
          filePointer.fileMetaIpnsName,
          parentFolder.folderKey
        );

        // Decrypt the file IPNS private key from FilePointer (or HKDF fallback)
        const { privateKey: fileIpnsPrivateKey, migratedIpnsPrivateKeyEncrypted } =
          await getFileIpnsPrivateKey(
            filePointer,
            auth.vaultKeypair.privateKey,
            auth.vaultKeypair.publicKey
          );

        // Compute the delete transform in the web tier (pure, no publish). The
        // transformed currentMetadata carries the pruned versions array; updates is
        // empty (current content unchanged). Routed through the SDK client.
        const {
          currentMetadata: prunedMetadata,
          updates,
          deletedCid,
        } = computeDeleteVersionUpdate(currentMetadata, versionIndex);

        try {
          // client.deleteFileVersion owns the file IPNS publish (CAS internally), the
          // conditional folder publish for lazy IPNS-key migration, folderTree
          // bookkeeping, and the folder:updated emission. The store's
          // children/sequenceNumber are written ONLY by the folder:updated subscription —
          // no direct store writes here. fileIpnsPrivateKey is zeroed in this finally
          // (T-47-01); sdk-core updateFileMetadata also zeroes its own copy.
          await getSdkClient().deleteFileVersion(parentFolder.ipnsName, fileId, versionIndex, {
            fileIpnsPrivateKey,
            currentMetadata: prunedMetadata,
            updates,
            deletedCid,
            maxVersionsPerFile: useVaultSettingsStore.getState().settings.maxVersionsPerFile,
            ...(migratedIpnsPrivateKeyEncrypted ? { migratedIpnsPrivateKeyEncrypted } : {}),
          });
        } finally {
          fileIpnsPrivateKey.fill(0);
        }

        // Unpin deleted version CID
        unpinFromIpfs(deletedCid).catch((err) =>
          logger.warn('[Versions] Unpin deleted CID failed:', err)
        );

        // Refresh quota
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
