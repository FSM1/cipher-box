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
import type { SealedChildRef } from '@cipherbox/core';
import { withRevocationGuard as sdkWithRevocationGuard } from '@cipherbox/sdk';
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
  const renameItemHandler = useCallback(async (_item: SealedChildRef, _newName: string) => {
    throw new Error('not implemented — phase 65 (shared folder rename requires Node write-chain)');
  }, []);

  /**
   * Update a file's content in the currently-viewed write-shared folder.
   *
   * File-only publish: the SDK publishes the file's own IPNS metadata (folder
   * children/sequence unchanged) and emits sharedFolder:updated so the
   * projection re-resolves the file. Throws on error (no setError shell) to
   * match the prior contract used by the file editor caller.
   */
  const updateSharedFileHandler = useCallback(
    async (_item: SealedChildRef, _newContent: Uint8Array): Promise<void> => {
      throw new Error('not implemented — phase 65 (shared file update requires Node read-chain)');
    },
    []
  );

  /**
   * Delete an item from the currently-viewed write-shared folder.
   */
  const deleteItemHandler = useCallback(async (_item: SealedChildRef) => {
    throw new Error('not implemented — phase 65 (shared folder delete requires Node write-chain)');
  }, []);

  /**
   * Move an item within the shared folder to a different destination subfolder.
   *
   * The vault private key reference is passed directly to the SDK — the SDK owns
   * all crypto (unwrap + re-encrypt) and key zeroing. The web does not clone or
   * zero it here (matches the established pattern; T-49-10 accepted).
   */
  const moveItemHandler = useCallback(
    async (_item: SealedChildRef, _destFolderId: string, _destIpnsName: string) => {
      throw new Error('not implemented — phase 65 (shared folder move requires Node write-chain)');
    },
    []
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
      _items: SealedChildRef[],
      _destFolderId: string,
      _destIpnsName: string,
      _clearSelection: () => void
    ) => {
      throw new Error(
        'not implemented — phase 65 (shared folder batch move requires Node write-chain)'
      );
    },
    []
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
