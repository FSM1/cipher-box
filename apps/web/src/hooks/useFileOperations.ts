import { useState, useCallback } from 'react';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useAuthStore } from '../stores/auth.store';
import { useQuotaStore } from '../stores/quota.store';
import { unpinFromIpfs } from '../lib/api/ipfs';
import * as folderService from '../services/folder.service';
import { reWrapForRecipients } from '../services/share.service';
import {
  createFileMetadata,
  resolveFileMetadata,
  updateFileMetadata,
  shouldCreateVersion,
  getFileIpnsPrivateKey,
} from '../services/file-metadata.service';
import type { FileIpnsRecordPayload } from '../services/file-metadata.service';
import type { FolderChild, FilePointer } from '@cipherbox/crypto';
import { unwrapKey, hexToBytes } from '@cipherbox/crypto';
import { getRootFolderState, resyncFolder, withConflictRetry } from './folder-helpers';
import type { FolderOperationState } from './folder-helpers';
import { useNotificationStore } from '../stores/notification.store';

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
   * Add a file to a folder after upload (v2).
   *
   * Creates per-file IPNS metadata, then registers FilePointer in folder.
   *
   * @param parentId - Parent folder ID ('root' or folder UUID)
   * @param fileData - Uploaded file data from upload service
   * @returns Created file pointer
   */
  const handleAddFile = useCallback(
    async (
      parentId: string,
      fileData: {
        cid: string;
        wrappedKey: string;
        iv: string;
        originalName: string;
        originalSize: number;
        mimeType?: string;
        encryptionMode?: 'GCM' | 'CTR';
      }
    ): Promise<FilePointer> => {
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

        // 1. Generate fileId and create per-file IPNS metadata
        const fileId = crypto.randomUUID();
        const { ipnsRecord, ipnsPrivateKeyEncrypted } = await createFileMetadata({
          fileId,
          cid: fileData.cid,
          fileKeyEncrypted: fileData.wrappedKey,
          fileIv: fileData.iv,
          size: fileData.originalSize,
          mimeType: fileData.mimeType ?? 'application/octet-stream',
          folderKey: parentFolder.folderKey,
          userPublicKey: auth.vaultKeypair.publicKey,
          encryptionMode: fileData.encryptionMode,
        });

        // 2. Register FilePointer in folder (batch publishes file + folder IPNS)
        //    On 409 conflict, re-sync the parent folder and retry once.
        const performAddFile = async (): Promise<{
          filePointer: FilePointer;
          newSequenceNumber: bigint;
        }> => {
          const freshFolders = useFolderStore.getState().folders;
          const freshVault = useVaultStore.getState();
          const freshParent =
            parentId === 'root'
              ? getRootFolderState(freshVault, freshFolders)
              : freshFolders[parentId];
          if (!freshParent) throw new Error('Parent folder not found');

          return folderService.addFileToFolder({
            parentFolderState: freshParent,
            fileId,
            name: fileData.originalName,
            fileIpnsRecord: ipnsRecord,
            ipnsPrivateKeyEncrypted,
          });
        };

        const { filePointer, newSequenceNumber } = await withConflictRetry(performAddFile, () =>
          resyncFolder(parentFolder.ipnsName, parentFolder.id)
        );

        // 3. Update local state with new child and sequence number
        const freshFolders2 = useFolderStore.getState().folders;
        const freshVault2 = useVaultStore.getState();
        const freshParent2 =
          parentId === 'root'
            ? getRootFolderState(freshVault2, freshFolders2)
            : freshFolders2[parentId];
        const updatedChildren: FolderChild[] = [...(freshParent2?.children ?? []), filePointer];
        const store = useFolderStore.getState();
        store.updateFolderChildren(parentId, updatedChildren);
        store.updateFolderSequence(parentId, newSequenceNumber);

        // 4. Post-upload: re-wrap file key for share recipients (fire-and-forget)
        // Unwrap the fileKey from the owner-wrapped key, then delegate to reWrapForRecipients
        (async () => {
          try {
            const authState = useAuthStore.getState();
            if (!authState.vaultKeypair) return;
            const fileKey = await unwrapKey(
              hexToBytes(fileData.wrappedKey),
              authState.vaultKeypair.privateKey
            );
            try {
              const { failedRecipients } = await reWrapForRecipients({
                folderIpnsName: parentFolder.ipnsName,
                folders: useFolderStore.getState().folders,
                currentFolderId: parentFolder.id,
                newItems: [{ keyType: 'file', itemId: fileId, plaintextKey: fileKey }],
              });
              if (failedRecipients.length > 0) {
                useNotificationStore
                  .getState()
                  .addNotification(
                    'warning',
                    `Failed to update share keys for ${failedRecipients.length} recipient(s). They may not be able to access the new file until you re-share.`
                  );
              }
            } finally {
              fileKey.fill(0);
            }
          } catch (err) {
            console.warn('[share] Post-upload file re-wrapping failed:', err);
          }
        })();

        setState({ isLoading: false, error: null });
        return filePointer;
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to add file';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  /**
   * Add multiple files to a folder after upload (v2 batch).
   *
   * Creates per-file IPNS metadata for each file, then registers all
   * FilePointers via a single batch IPNS publish.
   *
   * @param parentId - Parent folder ID ('root' or folder UUID)
   * @param filesData - Array of uploaded file data from upload service
   * @returns Created file pointers
   */
  const handleAddFiles = useCallback(
    async (
      parentId: string,
      filesData: Array<{
        cid: string;
        wrappedKey: string;
        iv: string;
        originalName: string;
        originalSize: number;
        mimeType?: string;
        encryptionMode?: 'GCM' | 'CTR';
      }>
    ): Promise<FilePointer[]> => {
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

        // 1. Create per-file IPNS metadata for each file
        const userPublicKey = auth.vaultKeypair.publicKey;
        const filesWithRecords = await Promise.all(
          filesData.map(async (f) => {
            const fileId = crypto.randomUUID();
            const { ipnsRecord, ipnsPrivateKeyEncrypted } = await createFileMetadata({
              fileId,
              cid: f.cid,
              fileKeyEncrypted: f.wrappedKey,
              fileIv: f.iv,
              size: f.originalSize,
              mimeType: f.mimeType ?? 'application/octet-stream',
              folderKey: parentFolder.folderKey,
              userPublicKey,
              encryptionMode: f.encryptionMode,
            });
            return {
              fileId,
              name: f.originalName,
              fileIpnsRecord: ipnsRecord,
              ipnsPrivateKeyEncrypted,
            };
          })
        );

        // 2. Register FilePointers in folder (batch publishes all IPNS records)
        //    On 409 conflict, re-sync the parent folder and retry once.
        const performAddFiles = async (): Promise<{
          filePointers: FilePointer[];
          newSequenceNumber: bigint;
        }> => {
          const freshFolders = useFolderStore.getState().folders;
          const freshVault = useVaultStore.getState();
          const freshParent =
            parentId === 'root'
              ? getRootFolderState(freshVault, freshFolders)
              : freshFolders[parentId];
          if (!freshParent) throw new Error('Parent folder not found');

          return folderService.addFilesToFolder({
            parentFolderState: freshParent,
            files: filesWithRecords,
          });
        };

        const { filePointers, newSequenceNumber } = await withConflictRetry(performAddFiles, () =>
          resyncFolder(parentFolder.ipnsName, parentFolder.id)
        );

        // 3. Update local state with new children and sequence number
        const store = useFolderStore.getState();
        const freshFolders2 = store.folders;
        const freshVault2 = useVaultStore.getState();
        const freshParent2 =
          parentId === 'root'
            ? getRootFolderState(freshVault2, freshFolders2)
            : freshFolders2[parentId];
        store.updateFolderChildren(parentId, [...(freshParent2?.children ?? []), ...filePointers]);
        store.updateFolderSequence(parentId, newSequenceNumber);

        // 4. Post-upload: re-wrap file keys for share recipients (fire-and-forget)
        (async () => {
          const newItems: Array<{
            keyType: 'file' | 'folder';
            itemId: string;
            plaintextKey: Uint8Array;
          }> = [];
          try {
            const authState = useAuthStore.getState();
            if (!authState.vaultKeypair) return;
            const privateKey = authState.vaultKeypair.privateKey;
            for (let i = 0; i < filesData.length; i++) {
              const fileKey = await unwrapKey(hexToBytes(filesData[i].wrappedKey), privateKey);
              newItems.push({
                keyType: 'file',
                itemId: filesWithRecords[i].fileId,
                plaintextKey: fileKey,
              });
            }
            const { failedRecipients } = await reWrapForRecipients({
              folderIpnsName: parentFolder.ipnsName,
              folders: useFolderStore.getState().folders,
              currentFolderId: parentFolder.id,
              newItems,
            });
            if (failedRecipients.length > 0) {
              useNotificationStore
                .getState()
                .addNotification(
                  'warning',
                  `Failed to update share keys for ${failedRecipients.length} recipient(s). They may not be able to access the new files until you re-share.`
                );
            }
          } catch (err) {
            console.warn('[share] Post-upload batch file re-wrapping failed:', err);
          } finally {
            for (const item of newItems) {
              item.plaintextKey.fill(0);
            }
          }
        })();

        setState({ isLoading: false, error: null });
        return filePointers;
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to add files';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

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

        let ipnsRecord: FileIpnsRecordPayload;
        let prunedCids: string[];
        try {
          // 5. Update file metadata and publish new IPNS record
          ({ ipnsRecord, prunedCids } = await updateFileMetadata({
            fileIpnsPrivateKey,
            fileMetaIpnsName: filePointer.fileMetaIpnsName,
            folderKey: parentFolder.folderKey,
            currentMetadata,
            updates: {
              cid: fileData.newCid,
              fileKeyEncrypted: fileData.newFileKeyEncrypted,
              fileIv: fileData.newFileIv,
              size: fileData.newSize,
            },
            createVersion,
          }));
        } finally {
          fileIpnsPrivateKey.fill(0);
        }

        // 6. Publish only the file IPNS record (folder metadata untouched!)
        await folderService.replaceFileInFolder({
          fileId: fileData.fileId,
          fileIpnsRecord: ipnsRecord,
          parentFolderState: parentFolder,
        });

        // 7. Update local state -- touch modifiedAt and persist migrated IPNS key if applicable
        const updatedChildren = parentFolder.children.map((child) => {
          if (child.type === 'file' && child.id === fileData.fileId) {
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

        const store = useFolderStore.getState();
        store.updateFolderChildren(parentId, updatedChildren);

        // 7b. Lazy migration: persist wrapped IPNS key to folder metadata on IPFS
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
              console.warn('Lazy IPNS key migration: folder re-publish failed, will retry:', err);
            });
        }

        // 8. Only unpin CIDs of pruned versions (excess beyond max 10)
        // Old CIDs stay pinned as version history (VER-01)
        for (const prunedCid of prunedCids) {
          unpinFromIpfs(prunedCid).catch(() => {});
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
    addFile: handleAddFile,
    addFiles: handleAddFiles,
    updateFile: handleUpdateFile,
  };
}
