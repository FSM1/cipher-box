/**
 * useSharedWriteOps -- Write operation handlers for shared folders.
 *
 * Handles upload, create folder, rename, and delete within shared folders.
 */

import { useCallback, type MutableRefObject } from 'react';
import type { FolderChild, FilePointer } from '@cipherbox/core';
import { unwrapKey, hexToBytes } from '@cipherbox/crypto';
import {
  uploadToSharedFolder,
  createSharedSubfolder,
  renameInSharedFolder,
  deleteFromSharedFolder,
  updateSharedFile,
  type SharedWriteContext,
  withRevocationGuard as sdkWithRevocationGuard,
  ShareKeyCache,
  buildSharedWriteContext,
} from '@cipherbox/sdk';
import { withConflictRetry } from './folder-helpers';
import { useAuthStore } from '../stores/auth.store';
import { fetchShareKeys, addShareKeys } from '../services/share.service';
import { apiAxios, apiUrl } from '../lib/api-config';
import { logger } from '../lib/logger';
import type { SharedListItem } from './useSharedNavigation';

/** Parse a 0x-prefixed or bare hex public key string into bytes. */
function parsePublicKey(keyHex: string): Uint8Array {
  const hex = keyHex.startsWith('0x') ? keyHex.slice(2) : keyHex;
  return hexToBytes(hex);
}

export type SharedWriteOpsParams = {
  currentShareId: string | null;
  folderKey: Uint8Array | null;
  ipnsName: string | null;
  currentSequenceNumber: bigint | null;
  sharedItems: SharedListItem[];
  folderChildrenRef: MutableRefObject<FolderChild[]>;
  sequenceNumberRef: MutableRefObject<bigint | null>;
  ipnsPrivateKeyRef: MutableRefObject<Uint8Array | null>;
  shareKeysCacheRef: MutableRefObject<ShareKeyCache>;
  setFolderChildren: (children: FolderChild[]) => void;
  setCurrentSequenceNumber: (seq: bigint | null) => void;
  setPermission: (perm: 'read' | 'write' | null) => void;
  setIsLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  refreshFolderContents: (ipnsName: string, folderKey: Uint8Array) => Promise<FolderChild[] | null>;
  handleRevocation: (silent: boolean) => void;
};

export function useSharedWriteOps(p: SharedWriteOpsParams) {
  /**
   * Re-sync the current shared folder for conflict retry.
   */
  const resyncSharedFolder = useCallback(async () => {
    if (!p.ipnsName || !p.folderKey) return;
    await p.refreshFolderContents(p.ipnsName, p.folderKey);
  }, [p.ipnsName, p.folderKey, p.refreshFolderContents]);

  /**
   * Build SharedWriteContext for SDK shared-write operations.
   * Returns null if any required state is missing.
   */
  const buildSharedWriteCtx = useCallback((): SharedWriteContext | null => {
    const currentIpnsKey = p.ipnsPrivateKeyRef.current;
    const auth = useAuthStore.getState();
    if (
      !currentIpnsKey ||
      !p.folderKey ||
      !p.ipnsName ||
      p.currentSequenceNumber === null ||
      !auth.vaultKeypair
    )
      return null;

    const shareItem = p.sharedItems.find((s) => s.share.shareId === p.currentShareId);
    if (!shareItem) return null;
    const ownerPubKey = parsePublicKey(shareItem.share.sharerPublicKey);

    return buildSharedWriteContext({
      ctx: {
        apiUrl,
        getAccessToken: async () => useAuthStore.getState().accessToken || '',
        axiosInstance: apiAxios,
      },
      folderKey: p.folderKey,
      ipnsPrivateKey: currentIpnsKey,
      ipnsName: p.ipnsName,
      sequenceNumber: p.currentSequenceNumber,
      children: p.folderChildrenRef.current,
      ownerPublicKey: ownerPubKey,
      recipientPublicKey: auth.vaultKeypair.publicKey,
      shareId: p.currentShareId!,
      addShareKeysFn: async (sid, keys) => {
        await addShareKeys(sid, keys);
        p.shareKeysCacheRef.current.invalidate(sid);
      },
    });
  }, [p.folderKey, p.ipnsName, p.currentSequenceNumber, p.currentShareId, p.sharedItems]);

  /**
   * Wrap a write operation with 403 revocation detection.
   */
  const withRevocationGuard = useCallback(
    async <T>(operation: () => Promise<T>): Promise<T> => {
      return sdkWithRevocationGuard(operation, () => p.handleRevocation(true));
    },
    [p.handleRevocation]
  );

  /**
   * Upload a file to the currently-viewed write-shared folder.
   */
  const uploadFileHandler = useCallback(
    async (file: File) => {
      const swCtx = buildSharedWriteCtx();
      if (!swCtx) {
        p.setError('Write access not available');
        return;
      }

      p.setIsLoading(true);
      p.setError(null);

      try {
        await withRevocationGuard(async () => {
          const data = new Uint8Array(await file.arrayBuffer());

          await withConflictRetry(
            async () => {
              const freshCtx = {
                ...swCtx,
                children: p.folderChildrenRef.current,
                sequenceNumber: p.sequenceNumberRef.current ?? 0n,
              };
              const result = await uploadToSharedFolder(freshCtx, {
                data,
                fileName: file.name,
                mimeType: file.type || undefined,
              });
              p.sequenceNumberRef.current = result.newSequenceNumber;
              p.folderChildrenRef.current = result.publishedChildren;
              p.setCurrentSequenceNumber(result.newSequenceNumber);
              p.setFolderChildren(result.publishedChildren);
            },
            async () => {
              await resyncSharedFolder();
            }
          );
        });
      } catch (err) {
        const message = (err as Error).message || 'Upload failed';
        if (!message.includes('write access revoked')) {
          p.setError(message);
        }
        logger.error('[SharedNav] Shared folder upload failed:', err);
      } finally {
        p.setIsLoading(false);
      }
    },
    [buildSharedWriteCtx, resyncSharedFolder, withRevocationGuard]
  );

  /**
   * Create a subfolder in the currently-viewed write-shared folder.
   */
  const createFolderHandler = useCallback(
    async (name: string) => {
      const swCtx = buildSharedWriteCtx();
      if (!swCtx) {
        p.setError('Write access not available');
        return;
      }

      p.setIsLoading(true);
      p.setError(null);

      try {
        await withRevocationGuard(async () => {
          await withConflictRetry(
            async () => {
              const freshCtx = {
                ...swCtx,
                children: p.folderChildrenRef.current,
                sequenceNumber: p.sequenceNumberRef.current ?? 0n,
              };
              const result = await createSharedSubfolder(freshCtx, { name });
              p.sequenceNumberRef.current = result.newSequenceNumber;
              p.folderChildrenRef.current = result.publishedChildren;
              p.setCurrentSequenceNumber(result.newSequenceNumber);
              p.setFolderChildren(result.publishedChildren);
            },
            async () => {
              await resyncSharedFolder();
            }
          );
        });
      } catch (err) {
        const message = (err as Error).message || 'Failed to create folder';
        if (!message.includes('write access revoked')) {
          p.setError(message);
        }
        logger.error('[SharedNav] Shared folder create failed:', err);
      } finally {
        p.setIsLoading(false);
      }
    },
    [buildSharedWriteCtx, resyncSharedFolder, withRevocationGuard]
  );

  /**
   * Rename an item in the currently-viewed write-shared folder.
   */
  const renameItemHandler = useCallback(
    async (item: FolderChild, newName: string) => {
      const swCtx = buildSharedWriteCtx();
      if (!swCtx) {
        p.setError('Write access not available');
        return;
      }

      p.setIsLoading(true);
      p.setError(null);

      try {
        await withRevocationGuard(async () => {
          await withConflictRetry(
            async () => {
              const freshCtx = {
                ...swCtx,
                children: p.folderChildrenRef.current,
                sequenceNumber: p.sequenceNumberRef.current ?? 0n,
              };
              const result = await renameInSharedFolder(freshCtx, { itemId: item.id, newName });
              p.sequenceNumberRef.current = result.newSequenceNumber;
              p.folderChildrenRef.current = result.publishedChildren;
              p.setCurrentSequenceNumber(result.newSequenceNumber);
              p.setFolderChildren(result.publishedChildren);
            },
            async () => {
              await resyncSharedFolder();
            }
          );
        });
      } catch (err) {
        const message = (err as Error).message || 'Failed to rename';
        if (!message.includes('write access revoked')) {
          p.setError(message);
        }
        logger.error('[SharedNav] Shared folder rename failed:', err);
      } finally {
        p.setIsLoading(false);
      }
    },
    [buildSharedWriteCtx, resyncSharedFolder, withRevocationGuard]
  );

  /**
   * Update a file's content in the currently-viewed write-shared folder.
   */
  const updateSharedFileHandler = useCallback(
    async (item: FilePointer, newContent: Uint8Array): Promise<void> => {
      if (!p.folderKey) throw new Error('Folder key not available');

      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) throw new Error('No keypair available');

      const shareItem = p.sharedItems.find((s) => s.share.shareId === p.currentShareId);
      if (!shareItem) throw new Error('Share not found');
      const ownerPublicKey = parsePublicKey(shareItem.share.sharerPublicKey);

      await withRevocationGuard(async () => {
        await updateSharedFile({
          ctx: {
            apiUrl,
            getAccessToken: async () => useAuthStore.getState().accessToken || '',
            axiosInstance: apiAxios,
          },
          folderKey: p.folderKey!,
          ownerPublicKey,
          recipientPublicKey: auth.vaultKeypair!.publicKey,
          shareId: p.currentShareId!,
          addShareKeysFn: async (sid, keys) => {
            await addShareKeys(sid, keys);
            p.shareKeysCacheRef.current.invalidate(sid);
          },
          filePointer: item,
          newContent,
          getFileIpnsKeyFn: async (itemId: string) => {
            const keys = await fetchShareKeys(p.currentShareId!);
            const exactMatch = keys.find((k) => k.keyType === 'file-ipns' && k.itemId === itemId);
            const ipnsKeyRecord =
              exactMatch ??
              (shareItem.share.itemType === 'file'
                ? keys.find((k) => k.keyType === 'file-ipns')
                : undefined);
            if (ipnsKeyRecord) {
              return unwrapKey(
                hexToBytes(ipnsKeyRecord.encryptedKey),
                auth.vaultKeypair!.privateKey
              );
            }
            if (item.ipnsPrivateKeyEncrypted) {
              try {
                return await unwrapKey(
                  hexToBytes(item.ipnsPrivateKeyEncrypted),
                  auth.vaultKeypair!.privateKey
                );
              } catch {
                return null;
              }
            }
            return null;
          },
        });
      });
    },
    [p.folderKey, p.currentShareId, p.sharedItems, withRevocationGuard]
  );

  /**
   * Delete an item from the currently-viewed write-shared folder.
   */
  const deleteItemHandler = useCallback(
    async (item: FolderChild) => {
      const swCtx = buildSharedWriteCtx();
      if (!swCtx) {
        p.setError('Write access not available');
        return;
      }

      p.setIsLoading(true);
      p.setError(null);

      try {
        await withRevocationGuard(async () => {
          await withConflictRetry(
            async () => {
              const freshCtx = {
                ...swCtx,
                children: p.folderChildrenRef.current,
                sequenceNumber: p.sequenceNumberRef.current ?? 0n,
              };
              const result = await deleteFromSharedFolder(freshCtx, { itemId: item.id });
              p.sequenceNumberRef.current = result.newSequenceNumber;
              p.folderChildrenRef.current = result.publishedChildren;
              p.setCurrentSequenceNumber(result.newSequenceNumber);
              p.setFolderChildren(result.publishedChildren);
            },
            async () => {
              await resyncSharedFolder();
            }
          );
        });
      } catch (err) {
        const message = (err as Error).message || 'Failed to delete';
        if (!message.includes('write access revoked')) {
          p.setError(message);
        }
        logger.error('[SharedNav] Shared folder delete failed:', err);
      } finally {
        p.setIsLoading(false);
      }
    },
    [buildSharedWriteCtx, resyncSharedFolder, withRevocationGuard]
  );

  return {
    uploadFile: uploadFileHandler,
    createFolder: createFolderHandler,
    renameItem: renameItemHandler,
    deleteItem: deleteItemHandler,
    updateSharedFile: updateSharedFileHandler,
  };
}
