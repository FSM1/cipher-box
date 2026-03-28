import { useState, useCallback } from 'react';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useAuthStore } from '../stores/auth.store';
import { useQuotaStore } from '../stores/quota.store';
import { unpinFromIpfs } from '../lib/api/ipfs';
import * as folderService from '../services/folder.service';
import {
  resolveFileMetadata,
  restoreVersion,
  deleteVersion,
  getFileIpnsPrivateKey,
} from '../services/file-metadata.service';
import type { FileIpnsRecordPayload } from '../services/file-metadata.service';
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

        let ipnsRecord: FileIpnsRecordPayload;
        let prunedCids: string[];
        try {
          // Call restoreVersion service function
          ({ ipnsRecord, prunedCids } = await restoreVersion({
            fileIpnsPrivateKey,
            fileMetaIpnsName: filePointer.fileMetaIpnsName,
            folderKey: parentFolder.folderKey,
            currentMetadata,
            versionIndex,
          }));
        } finally {
          fileIpnsPrivateKey.fill(0);
        }

        // Publish the IPNS record (folder metadata untouched)
        await folderService.replaceFileInFolder({
          fileId,
          fileIpnsRecord: ipnsRecord,
          parentFolderState: parentFolder,
        });

        // Update local folder state (modifiedAt and migrated IPNS key on FilePointer)
        const updatedChildren = parentFolder.children.map((child) => {
          if (child.type === 'file' && child.id === fileId) {
            return {
              ...child,
              modifiedAt: Date.now(),
              ...(migratedIpnsPrivateKeyEncrypted
                ? { ipnsPrivateKeyEncrypted: migratedIpnsPrivateKeyEncrypted }
                : {}),
            };
          }
          return child;
        });
        useFolderStore.getState().updateFolderChildren(parentId, updatedChildren);

        // Lazy migration: persist wrapped IPNS key to folder metadata on IPFS
        if (migratedIpnsPrivateKeyEncrypted) {
          folderService
            .updateFolderMetadata({
              folderId: parentFolder.id,
              children: updatedChildren,
              folderKey: parentFolder.folderKey,
              ipnsPrivateKey: parentFolder.ipnsPrivateKey,
              ipnsName: parentFolder.ipnsName,
              sequenceNumber: parentFolder.sequenceNumber,
            })
            .then(({ newSequenceNumber }) => {
              useFolderStore.getState().updateFolderSequence(parentId, newSequenceNumber);
            })
            .catch((err) => {
              logger.warn(
                '[Versions] Lazy IPNS key migration: folder re-publish failed, will retry:',
                err
              );
            });
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

        let ipnsRecord: FileIpnsRecordPayload;
        let deletedCid: string;
        try {
          // Call deleteVersion service function
          ({ ipnsRecord, deletedCid } = await deleteVersion({
            fileIpnsPrivateKey,
            fileMetaIpnsName: filePointer.fileMetaIpnsName,
            folderKey: parentFolder.folderKey,
            currentMetadata,
            versionIndex,
          }));
        } finally {
          fileIpnsPrivateKey.fill(0);
        }

        // Publish the IPNS record (folder metadata untouched)
        await folderService.replaceFileInFolder({
          fileId,
          fileIpnsRecord: ipnsRecord,
          parentFolderState: parentFolder,
        });

        // Lazy migration: persist wrapped IPNS key to folder metadata on IPFS
        if (migratedIpnsPrivateKeyEncrypted) {
          const updatedChildren = parentFolder.children.map((child) => {
            if (child.type === 'file' && child.id === fileId) {
              return { ...child, ipnsPrivateKeyEncrypted: migratedIpnsPrivateKeyEncrypted };
            }
            return child;
          });
          useFolderStore.getState().updateFolderChildren(parentId, updatedChildren);

          folderService
            .updateFolderMetadata({
              folderId: parentFolder.id,
              children: updatedChildren,
              folderKey: parentFolder.folderKey,
              ipnsPrivateKey: parentFolder.ipnsPrivateKey,
              ipnsName: parentFolder.ipnsName,
              sequenceNumber: parentFolder.sequenceNumber,
            })
            .then(({ newSequenceNumber }) => {
              useFolderStore.getState().updateFolderSequence(parentId, newSequenceNumber);
            })
            .catch((err) => {
              logger.warn(
                '[Versions] Lazy IPNS key migration: folder re-publish failed, will retry:',
                err
              );
            });
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
