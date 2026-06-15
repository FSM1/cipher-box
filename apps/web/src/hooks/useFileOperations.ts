import { useState, useCallback } from 'react';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useAuthStore } from '../stores/auth.store';
import { useQuotaStore } from '../stores/quota.store';
import { unpinFromIpfs } from '../lib/api/ipfs';
import { getSdkClient, ensureFolderRegistered } from '../lib/sdk-provider';
import { reWrapForRecipients } from '../services/share.service';
import {
  resolveFileMetadata,
  shouldCreateVersion,
  getFileIpnsPrivateKey,
} from '../services/file-metadata.service';
import type { FilePointer } from '@cipherbox/core';
import { unwrapKey, hexToBytes } from '@cipherbox/crypto';
import { getRootFolderState } from './folder-helpers';
import type { FolderOperationState } from './folder-helpers';
import { useVaultSettingsStore } from '../stores/vault-settings.store';
import { logger } from '../lib/logger';

/**
 * React hook for file add/update operations.
 *
 * Returns loading/error state and operation callbacks.
 */
export function useFileOperations() {
  const [state, setState] = useState<FolderOperationState>({
    isLoading: false,
    error: null,
  });

  /**
   * Update a file's content in-place (v2: re-encrypt, update file IPNS, folder untouched).
   *
   * Old CIDs are preserved as version history (VER-01). Only pruned versions
   * (excess beyond max 10) have their CIDs unpinned.
   *
   * NOTE: No conflict detection here -- handleUpdateFile publishes only the
   * per-file IPNS record. Folder metadata is NOT touched, so no 409 is possible.
   *
   * @param parentId - Parent folder ID ('root' or folder UUID)
   * @param fileData - New file data after re-encryption
   * @returns Resolves when the update is complete
   */
  const handleUpdateFile = useCallback(
    async (
      parentId: string,
      fileData: {
        fileId: string;
        newCid: string;
        newFileKeyEncrypted: string;
        newFileIv: string;
        newSize: number;
        newEncryptionMode?: 'GCM' | 'CTR';
        forceVersion?: boolean; // true for web re-upload, false/undefined for text editor
      }
    ): Promise<void> => {
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

        // Seed the SDK folderTree from the store before routing through the client.
        // Navigation/read populate only the Zustand store; client.replaceFile gates on
        // folderTree.get() and throws 'Folder not loaded' otherwise. No-op if already
        // tracked. (Mirrors useFolderMutations / useDropUpload.)
        ensureFolderRegistered(parentFolder);

        // 1. Find the FilePointer in parent's children
        const filePointer = parentFolder.children.find(
          (c) => c.type === 'file' && c.id === fileData.fileId
        ) as FilePointer | undefined;

        if (!filePointer) {
          throw new Error('File not found in folder');
        }

        // 2. Resolve current file metadata from IPNS
        const { metadata: currentMetadata } = await resolveFileMetadata(
          filePointer.fileMetaIpnsName,
          parentFolder.folderKey
        );

        // 3. Decrypt the file IPNS private key from FilePointer (or HKDF fallback)
        const { privateKey: fileIpnsPrivateKey, migratedIpnsPrivateKeyEncrypted } =
          await getFileIpnsPrivateKey(
            filePointer,
            auth.vaultKeypair.privateKey,
            auth.vaultKeypair.publicKey
          );

        // 4. Determine whether to create a version entry
        const createVersion = shouldCreateVersion(currentMetadata, fileData.forceVersion ?? false);

        let prunedCids: string[];
        try {
          // 5/6. Route the file replace through the SDK client. client.replaceFile owns
          //    the file IPNS publish (via sdk-core updateFileMetadata, CAS internally),
          //    the folder touch (bump modifiedAt on the FilePointer + persist any migrated
          //    IPNS key), folderTree bookkeeping, and the folder:updated emission. The
          //    store's children/sequenceNumber are written ONLY by the folder:updated
          //    subscription — no direct store writes here (PR #489 desync closed).
          //    fileIpnsPrivateKey is resolved above and zeroed in this finally (T-47-01);
          //    sdk-core updateFileMetadata also zeroes its own copy.
          ({ prunedCids } = await getSdkClient().replaceFile(
            parentFolder.ipnsName,
            fileData.fileId,
            {
              fileIpnsPrivateKey,
              currentMetadata,
              updates: {
                cid: fileData.newCid,
                fileKeyEncrypted: fileData.newFileKeyEncrypted,
                fileIv: fileData.newFileIv,
                size: fileData.newSize,
                ...(fileData.newEncryptionMode
                  ? { encryptionMode: fileData.newEncryptionMode }
                  : {}),
              },
              createVersion,
              maxVersionsPerFile: useVaultSettingsStore.getState().settings.maxVersionsPerFile,
              ...(migratedIpnsPrivateKeyEncrypted ? { migratedIpnsPrivateKeyEncrypted } : {}),
            }
          ));
        } finally {
          fileIpnsPrivateKey.fill(0);
        }

        // 8. Re-wrap new file key for share recipients (fire-and-forget)
        (async () => {
          try {
            const authState = useAuthStore.getState();
            if (!authState.vaultKeypair) return;
            const fileKey = await unwrapKey(
              hexToBytes(fileData.newFileKeyEncrypted),
              authState.vaultKeypair.privateKey
            );
            try {
              await reWrapForRecipients({
                folderIpnsName: parentFolder.ipnsName,
                folders: useFolderStore.getState().folders,
                currentFolderId: parentId === 'root' ? null : parentId,
                newItems: [{ keyType: 'file', itemId: fileData.fileId, plaintextKey: fileKey }],
              });
            } finally {
              fileKey.fill(0);
            }
          } catch (err) {
            logger.warn('[share] Post-update re-wrap failed:', err);
          }
        })();

        // 9. Only unpin CIDs of pruned versions (excess beyond max 10)
        // Old CIDs stay pinned as version history (VER-01)
        for (const prunedCid of prunedCids) {
          unpinFromIpfs(prunedCid).catch((err) =>
            logger.warn('[FileOps] Unpin pruned CID failed:', err)
          );
        }

        // Refresh quota
        useQuotaStore.getState().fetchQuota();

        setState({ isLoading: false, error: null });
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to update file';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  return {
    ...state,
    updateFile: handleUpdateFile,
  };
}
