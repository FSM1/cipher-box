/**
 * useSharedWriteOps -- Write operation handlers for shared folders.
 *
 * Handles upload, create folder, rename, update, and delete within shared
 * folders. Every handler routes through the SDK client's shared-folder methods
 * (`getSdkClient().<method>(currentShareId, args)`) and reads NOTHING back
 * (REQ-3, phase 48): the SDK owns publish + sequence + CAS retry. The
 * `folderChildrenRef`/`sequenceNumberRef` projections are fed solely by the
 * `sharedFolder:updated` subscription in `useSharedNavigation` — never written
 * here. This mirrors the Phase-47 owned-path consolidation
 * (useFileOperations/useFileVersions).
 */

import { useCallback } from 'react';
import type { FolderChild, FilePointer } from '@cipherbox/core';
import { unwrapKey, hexToBytes } from '@cipherbox/crypto';
import { withRevocationGuard as sdkWithRevocationGuard } from '@cipherbox/sdk';
import { useAuthStore } from '../stores/auth.store';
import { fetchShareKeys } from '../services/share.service';
import { getSdkClient } from '../lib/sdk-provider';
import { logger } from '../lib/logger';
import type { SharedListItem } from './useSharedNavigation';

export type SharedWriteOpsParams = {
  currentShareId: string | null;
  sharedItems: SharedListItem[];
  setIsLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  handleRevocation: (silent: boolean) => void;
};

export function useSharedWriteOps(p: SharedWriteOpsParams) {
  /**
   * Wrap a write operation with 403 revocation detection.
   * Orthogonal to CAS (which the SDK owns) — kept on the web side because the
   * revocation UX (zero key, flip to read-only) is web state.
   */
  const withRevocationGuard = useCallback(
    async <T>(operation: () => Promise<T>): Promise<T> => {
      return sdkWithRevocationGuard(operation, () => p.handleRevocation(true));
    },
    [p.handleRevocation]
  );

  /**
   * Run a folder write op through the SDK client. State updates (children /
   * sequence) arrive via the sharedFolder:updated subscription — nothing is read
   * back here.
   */
  const runWrite = useCallback(
    async (op: (shareId: string) => Promise<void>, failMessage: string): Promise<boolean> => {
      const shareId = p.currentShareId;
      if (!shareId) {
        p.setError('Write access not available');
        return false;
      }
      p.setIsLoading(true);
      p.setError(null);
      try {
        await withRevocationGuard(() => op(shareId));
        return true;
      } catch (err) {
        const message = (err as Error).message || failMessage;
        if (!message.includes('write access revoked')) {
          p.setError(message);
        }
        logger.error(`[SharedNav] ${failMessage}:`, err);
        return false;
      } finally {
        p.setIsLoading(false);
      }
    },
    [p.currentShareId, p.setError, p.setIsLoading, withRevocationGuard]
  );

  /**
   * Upload a file to the currently-viewed write-shared folder.
   */
  const uploadFileHandler = useCallback(
    async (file: File) => {
      await runWrite(async (shareId) => {
        const data = new Uint8Array(await file.arrayBuffer());
        await getSdkClient().uploadToSharedFolder(shareId, {
          data,
          fileName: file.name,
          mimeType: file.type || undefined,
        });
      }, 'Shared folder upload failed');
    },
    [runWrite]
  );

  /**
   * Create a subfolder in the currently-viewed write-shared folder.
   */
  const createFolderHandler = useCallback(
    async (name: string) => {
      await runWrite(async (shareId) => {
        await getSdkClient().createSharedSubfolder(shareId, { name });
      }, 'Shared folder create failed');
    },
    [runWrite]
  );

  /**
   * Rename an item in the currently-viewed write-shared folder.
   */
  const renameItemHandler = useCallback(
    async (item: FolderChild, newName: string) => {
      await runWrite(async (shareId) => {
        await getSdkClient().renameInSharedFolder(shareId, { itemId: item.id, newName });
      }, 'Shared folder rename failed');
    },
    [runWrite]
  );

  /**
   * Update a file's content in the currently-viewed write-shared folder.
   *
   * File-only publish: the SDK publishes the file's own IPNS metadata (folder
   * children/sequence unchanged) and emits sharedFolder:updated so the
   * projection re-resolves the file. Throws on error (no setError shell) to
   * match the prior contract used by the file editor caller.
   */
  const updateSharedFileHandler = useCallback(
    async (item: FilePointer, newContent: Uint8Array): Promise<void> => {
      const shareId = p.currentShareId;
      if (!shareId) throw new Error('Write access not available');

      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) throw new Error('No keypair available');

      const shareItem = p.sharedItems.find((s) => s.share.shareId === shareId);
      if (!shareItem) throw new Error('Share not found');

      await withRevocationGuard(async () => {
        await getSdkClient().updateSharedFile(shareId, {
          filePointer: item,
          newContent,
          getFileIpnsKeyFn: async (itemId: string) => {
            const keys = await fetchShareKeys(shareId);
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
    [p.currentShareId, p.sharedItems, withRevocationGuard]
  );

  /**
   * Delete an item from the currently-viewed write-shared folder.
   */
  const deleteItemHandler = useCallback(
    async (item: FolderChild) => {
      await runWrite(async (shareId) => {
        await getSdkClient().deleteFromSharedFolder(shareId, { itemId: item.id });
      }, 'Shared folder delete failed');
    },
    [runWrite]
  );

  /**
   * Move an item within the shared folder to a different destination subfolder.
   *
   * The vault private key reference is passed directly to the SDK — the SDK owns
   * all crypto (unwrap + re-encrypt) and key zeroing. The web does not clone or
   * zero it here (matches the established pattern; T-49-10 accepted).
   */
  const moveItemHandler = useCallback(
    async (item: FolderChild, destFolderId: string, destIpnsName: string) => {
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) {
        p.setError('No keypair available');
        return;
      }
      await runWrite(async (shareId) => {
        await getSdkClient().moveInSharedFolder(shareId, {
          itemId: item.id,
          destFolderId,
          destIpnsName,
          vaultPrivateKey: auth.vaultKeypair!.privateKey,
          getShareKeysFn: fetchShareKeys,
        });
      }, 'Shared folder move failed');
    },
    [runWrite, p.setError]
  );

  /**
   * Move multiple items to a destination subfolder by looping moveInSharedFolder
   * per item (mirrors useFolderMutations.handleMoveItems — no dedicated SDK batch op).
   *
   * Per-item failure stops the loop and surfaces the error (T-49-11). Calls
   * clearSelection() on full success.
   */
  const batchMoveItemsHandler = useCallback(
    async (
      items: FolderChild[],
      destFolderId: string,
      destIpnsName: string,
      clearSelection: () => void
    ) => {
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) {
        p.setError('No keypair available');
        return;
      }
      if (items.length === 0) return;

      const ok = await runWrite(async (shareId) => {
        for (const item of items) {
          await getSdkClient().moveInSharedFolder(shareId, {
            itemId: item.id,
            destFolderId,
            destIpnsName,
            vaultPrivateKey: auth.vaultKeypair!.privateKey,
            getShareKeysFn: fetchShareKeys,
          });
        }
      }, 'Shared folder batch move failed');

      // Clear the selection only on full success — on failure (a per-item error
      // stops the loop) keep the selection so the user can retry.
      if (ok) clearSelection();
    },
    [runWrite, p.setError]
  );

  return {
    uploadFile: uploadFileHandler,
    createFolder: createFolderHandler,
    renameItem: renameItemHandler,
    deleteItem: deleteItemHandler,
    updateSharedFile: updateSharedFileHandler,
    moveItem: moveItemHandler,
    batchMoveItems: batchMoveItemsHandler,
  };
}
