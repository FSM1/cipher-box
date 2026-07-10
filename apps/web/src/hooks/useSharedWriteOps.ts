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
import { unwrapKey, hexToBytes } from '@cipherbox/crypto';
import { getSdkClient } from '../lib/sdk-provider';
import { useAuthStore } from '../stores/auth.store';
import { fetchShareKeys } from '../services/share.service';
import { logger } from '../lib/logger';
import type { SharedListItem } from './useSharedNavigation';

/**
 * Resolve a child item's write-body UUID (childNodeId) from its
 * `SealedChildRef` via `client.resolveNodeIdentity` (D-07, 68.2-08) --
 * `id`/`kind` are plaintext on the PublishedNode envelope (NODE-03), so no
 * readKey/decryption is needed; the SDK facade resolves+parses the envelope
 * internally.
 *
 * 73-04 SC3: `resolveNodeIdentity` now routes through `gatedResolveChild`
 * (ROT-07 anti-rollback floor), so the full `SealedChildRef` -- not just its
 * bare `ipnsName` -- must be threaded through so the gate can source
 * `generation`/`versionFloor` from the PARENT mirror.
 */
async function resolveChildNodeId(item: SealedChildRef): Promise<string> {
  const identity = await getSdkClient().resolveNodeIdentity(item);
  if (!identity) {
    throw new Error(`Cannot resolve item ${item.ipnsName} (revoked or not found)`);
  }
  return identity.nodeId;
}

/**
 * Resolve a shared file's re-wrapped IPNS private key from `share_keys`
 * (keyType `file-ipns`, itemId = file's ipnsName) -- fallback path used by
 * `updateSharedFile` only when the write-chain walk finds no `WriteChildRef`
 * for the file. Mirrors `useSharedNavigationActions.ts`'s
 * `resolveFolderIpnsPrivateKey` (folder-ipns analog).
 */
async function resolveFileIpnsKey(itemId: string, shareId: string): Promise<Uint8Array | null> {
  const vaultPrivateKey = useAuthStore.getState().vaultKeypair?.privateKey;
  if (!vaultPrivateKey) return null;
  try {
    const keys = await fetchShareKeys(shareId);
    const entry = keys.find((k) => k.keyType === 'file-ipns' && k.itemId === itemId);
    if (!entry) return null;
    return await unwrapKey(hexToBytes(entry.encryptedKey), vaultPrivateKey);
  } catch (err) {
    logger.error('[SharedNav] Failed to resolve file IPNS key:', err);
    return null;
  }
}

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
    async (item: SealedChildRef, newName: string) => {
      await runWrite(async (shareId) => {
        await getSdkClient().renameInSharedFolder(shareId, {
          itemId: item.ipnsName,
          newName,
        });
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
    async (item: SealedChildRef, newContent: Uint8Array): Promise<void> => {
      const shareId = p.currentShareId;
      if (!shareId) {
        throw new Error('Write access not available');
      }
      await withRevocationGuard(() =>
        getSdkClient().updateSharedFile(shareId, {
          filePointer: item,
          newContent,
          getFileIpnsKeyFn: (itemId) => resolveFileIpnsKey(itemId, shareId),
        })
      );
    },
    [p.currentShareId, withRevocationGuard]
  );

  /**
   * Delete an item from the currently-viewed write-shared folder.
   *
   * Resolves the item's write-body UUID (childNodeId) from its PublishedNode
   * envelope before calling the client -- deleteFromSharedFolder fails closed
   * if childNodeId is missing (T-68.1-10-01).
   */
  const deleteItemHandler = useCallback(
    async (item: SealedChildRef) => {
      await runWrite(async (shareId) => {
        const childNodeId = await resolveChildNodeId(item);
        await getSdkClient().deleteFromSharedFolder(shareId, {
          itemId: item.ipnsName,
          childNodeId,
        });
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
    async (item: SealedChildRef, destFolderId: string, destIpnsName: string) => {
      await runWrite(async (shareId) => {
        const vaultPrivateKey = useAuthStore.getState().vaultKeypair?.privateKey;
        if (!vaultPrivateKey) {
          throw new Error('Not authenticated');
        }
        await getSdkClient().moveInSharedFolder(shareId, {
          itemId: item.ipnsName,
          destFolderId,
          destIpnsName,
          vaultPrivateKey,
        });
      }, 'Shared folder move failed');
    },
    [runWrite]
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
      items: SealedChildRef[],
      destFolderId: string,
      destIpnsName: string,
      clearSelection: () => void
    ) => {
      const shareId = p.currentShareId;
      if (!shareId) {
        p.setError('Write access not available');
        return;
      }
      const vaultPrivateKey = useAuthStore.getState().vaultKeypair?.privateKey;
      if (!vaultPrivateKey) {
        p.setError('Not authenticated');
        return;
      }
      p.setIsLoading(true);
      p.setError(null);
      try {
        for (const item of items) {
          await withRevocationGuard(() =>
            getSdkClient().moveInSharedFolder(shareId, {
              itemId: item.ipnsName,
              destFolderId,
              destIpnsName,
              vaultPrivateKey,
            })
          );
        }
        clearSelection();
      } catch (err) {
        const message = (err as Error).message || 'Shared folder batch move failed';
        if (!message.includes('write access revoked')) {
          p.setError(message);
        }
        logger.error('[SharedNav] Shared folder batch move failed:', err);
      } finally {
        p.setIsLoading(false);
      }
    },
    [p.currentShareId, p.setError, p.setIsLoading, withRevocationGuard]
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
