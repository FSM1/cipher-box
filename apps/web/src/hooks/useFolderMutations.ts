import { useState, useCallback } from 'react';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useAuthStore } from '../stores/auth.store';
import * as folderService from '../services/folder.service';
import { reWrapForRecipients } from '../services/share.service';
import { addManyToBin } from '../services/bin.service';
import type { FolderNode } from '../stores/folder.store';
import type { FolderEntry, FolderChild } from '@cipherbox/crypto';
import {
  MAX_FOLDER_DEPTH,
  getRootFolderState,
  resyncFolder,
  withConflictRetry,
} from './folder-helpers';
import type { FolderOperationState } from './folder-helpers';

/**
 * Build a breadcrumb-style path string for a folder by walking up the tree.
 * e.g., "My Vault / Documents / Reports"
 */
function buildFolderPath(folderId: string): string {
  const folders = useFolderStore.getState().folders;
  const parts: string[] = [];
  let currentId: string | null = folderId;

  while (currentId !== null) {
    const folder: FolderNode | undefined = folders[currentId];
    if (!folder) break;
    parts.unshift(folder.name);
    currentId = folder.parentId;
  }

  return parts.length > 0 ? parts.join(' / ') : 'My Vault';
}

/**
 * React hook for folder CRUD operations (create, rename, move, delete).
 *
 * Returns loading/error state and operation callbacks.
 */
export function useFolderMutations() {
  const [state, setState] = useState<FolderOperationState>({
    isLoading: false,
    error: null,
  });

  /**
   * Create a new folder.
   *
   * @param name - Folder name
   * @param parentId - Parent folder ID (null for root, or folder UUID)
   * @returns Created folder entry
   * @throws Error if depth limit exceeded or creation fails
   */
  const handleCreate = useCallback(
    async (name: string, parentId: string | null): Promise<FolderEntry> => {
      setState({ isLoading: true, error: null });
      try {
        const folders = useFolderStore.getState().folders;
        const vault = useVaultStore.getState();
        const auth = useAuthStore.getState();

        // Validate depth limit before creating (FOLD-03)
        const parentDepth = folderService.getDepth(parentId, folders);
        if (parentDepth >= MAX_FOLDER_DEPTH) {
          throw new Error(`Cannot create folder: maximum depth of ${MAX_FOLDER_DEPTH} exceeded`);
        }

        // Get user's ECIES keypair for vault cryptographic operations (public + private keys stored in memory after login)
        // The public key is used here for key wrapping; the private key remains client-side for decryption operations.
        if (!auth.vaultKeypair) {
          throw new Error('No ECIES keypair available - please log in again');
        }
        const userPublicKey = auth.vaultKeypair.publicKey;

        // Create the folder (generates keys, wraps with user public key, TEE-encrypts IPNS key)
        const { folder, ipnsPrivateKey, folderKey, encryptedIpnsPrivateKey, keyEpoch } =
          await folderService.createFolder({
            parentFolderId: parentId,
            name,
            userPublicKey,
            folders,
          });

        // Get parent folder state
        const parentFolder =
          parentId && folders[parentId] ? folders[parentId] : getRootFolderState(vault, folders);

        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        // Update parent folder metadata and publish IPNS (with conflict retry)
        const performParentUpdate = async () => {
          const freshState = useFolderStore.getState();
          const freshParent =
            parentId && freshState.folders[parentId]
              ? freshState.folders[parentId]
              : getRootFolderState(useVaultStore.getState(), freshState.folders);
          if (!freshParent) throw new Error('Parent folder not found');
          const freshChildren = [...freshParent.children, folder];
          const { newSequenceNumber } = await folderService.updateFolderMetadata({
            folderId: freshParent.id,
            children: freshChildren,
            folderKey: freshParent.folderKey,
            ipnsPrivateKey: freshParent.ipnsPrivateKey,
            ipnsName: freshParent.ipnsName,
            sequenceNumber: freshParent.sequenceNumber,
          });
          return { children: freshChildren, newSequenceNumber };
        };

        const parentResult = await withConflictRetry(performParentUpdate, () =>
          resyncFolder(parentFolder.ipnsName, parentFolder.id)
        );

        // First publish for the new folder's own IPNS record with TEE-encrypted key
        // This sends encryptedIpnsPrivateKey to backend for TEE republish enrollment
        const { newSequenceNumber: newFolderSequence } = await folderService.updateFolderMetadata({
          folderId: folder.id,
          children: [],
          folderKey,
          ipnsPrivateKey,
          ipnsName: folder.ipnsName,
          sequenceNumber: 0n,
          encryptedIpnsPrivateKey,
          keyEpoch,
        });

        // Update local state - add new folder to tree and persist sequence
        useFolderStore.getState().updateFolderChildren(parentFolder.id, parentResult.children);
        useFolderStore
          .getState()
          .updateFolderSequence(parentFolder.id, parentResult.newSequenceNumber);

        // Also add the new folder node to the store (with its decrypted keys)
        const newFolderNode: FolderNode = {
          id: folder.id,
          name: folder.name,
          ipnsName: folder.ipnsName,
          parentId: parentFolder.id,
          children: [],
          isLoaded: true,
          isLoading: false,
          sequenceNumber: newFolderSequence,
          folderKey,
          ipnsPrivateKey,
        };
        useFolderStore.getState().setFolder(newFolderNode);

        // Post-create: re-wrap new subfolder key for share recipients (fire-and-forget)
        reWrapForRecipients({
          folderIpnsName: parentFolder.ipnsName,
          folders: useFolderStore.getState().folders,
          currentFolderId: parentFolder.id,
          newItems: [{ keyType: 'folder', itemId: folder.id, plaintextKey: folderKey }],
        }).catch((err) => {
          console.warn('[share] Post-create subfolder re-wrapping failed:', err);
        });

        setState({ isLoading: false, error: null });
        return folder;
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to create folder';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  /**
   * Rename a file or folder.
   *
   * @param itemId - ID of item to rename
   * @param itemType - 'file' or 'folder'
   * @param newName - New name
   * @param parentId - Parent folder ID
   */
  const handleRename = useCallback(
    async (
      itemId: string,
      itemType: 'file' | 'folder',
      newName: string,
      parentId: string
    ): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const getParentFolder = () => {
          const freshState = useFolderStore.getState();
          return parentId === 'root'
            ? getRootFolderState(useVaultStore.getState(), freshState.folders)
            : freshState.folders[parentId];
        };

        const parentFolder = getParentFolder();
        if (!parentFolder) throw new Error('Parent folder not found');

        const performRename = async (): Promise<{ newSequenceNumber: bigint }> => {
          const freshParent = getParentFolder();
          if (!freshParent) throw new Error('Parent folder not found');
          if (itemType === 'folder') {
            return await folderService.renameFolder({
              folderId: itemId,
              newName,
              parentFolderState: freshParent,
            });
          } else {
            return await folderService.renameFile({
              fileId: itemId,
              newName,
              parentFolderState: freshParent,
            });
          }
        };

        const renameResult = await withConflictRetry(performRename, () =>
          resyncFolder(parentFolder.ipnsName, parentFolder.id)
        );

        if (itemType === 'folder') {
          // Update local folder state name
          useFolderStore.getState().updateFolderName(itemId, newName);
        }

        // Update parent's children with new name using fresh state
        const freshParent = getParentFolder();
        if (freshParent) {
          const updatedChildren = freshParent.children.map((child) => {
            if (child.id === itemId) {
              return { ...child, name: newName, modifiedAt: Date.now() };
            }
            return child;
          });
          useFolderStore.getState().updateFolderChildren(parentId, updatedChildren);
        }

        // Persist the new sequence number so subsequent operations use the correct value
        useFolderStore.getState().updateFolderSequence(parentId, renameResult.newSequenceNumber);

        setState({ isLoading: false, error: null });
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to rename';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  /**
   * Move a file or folder to a different parent.
   *
   * @param itemId - ID of item to move
   * @param itemType - 'file' or 'folder'
   * @param sourceParentId - Current parent folder ID
   * @param destParentId - Destination parent folder ID
   */
  const handleMove = useCallback(
    async (
      itemId: string,
      itemType: 'file' | 'folder',
      sourceParentId: string,
      destParentId: string
    ): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const getSourceFolder = () => {
          const freshState = useFolderStore.getState();
          return sourceParentId === 'root'
            ? getRootFolderState(useVaultStore.getState(), freshState.folders)
            : freshState.folders[sourceParentId];
        };

        const getDestFolder = () => {
          const freshState = useFolderStore.getState();
          return destParentId === 'root'
            ? getRootFolderState(useVaultStore.getState(), freshState.folders)
            : freshState.folders[destParentId];
        };

        const sourceFolder = getSourceFolder();
        const destFolder = getDestFolder();
        if (!sourceFolder || !destFolder) {
          throw new Error('Source or destination folder not found');
        }

        const performMove = async (): Promise<{
          destSequenceNumber: bigint;
          sourceSequenceNumber: bigint;
        }> => {
          const freshSource = getSourceFolder();
          const freshDest = getDestFolder();
          if (!freshSource || !freshDest) throw new Error('Source or destination folder not found');
          const folders = useFolderStore.getState().folders;
          if (itemType === 'folder') {
            return await folderService.moveFolder({
              folderId: itemId,
              sourceFolderState: freshSource,
              destFolderState: freshDest,
              folders,
            });
          } else {
            return await folderService.moveFile({
              fileId: itemId,
              sourceFolderState: freshSource,
              destFolderState: freshDest,
            });
          }
        };

        const moveResult = await withConflictRetry(performMove, async () => {
          await Promise.all([
            resyncFolder(sourceFolder.ipnsName, sourceFolder.id),
            sourceFolder.id !== destFolder.id
              ? resyncFolder(destFolder.ipnsName, destFolder.id)
              : Promise.resolve(),
          ]);
        });

        // Save the moved item BEFORE updating source children (otherwise it's already gone)
        const freshSourceBeforeUpdate = getSourceFolder();
        const movedItem = freshSourceBeforeUpdate?.children.find((c) => c.id === itemId);

        if (itemType === 'folder') {
          // Update the moved folder's parentId in local state
          const freshFolders = useFolderStore.getState().folders;
          const movedFolder = freshFolders[itemId];
          if (movedFolder) {
            useFolderStore.getState().setFolder({
              ...movedFolder,
              parentId: destParentId,
            });
          }
        }

        // Update source folder's children (remove item)
        if (freshSourceBeforeUpdate) {
          const updatedSourceChildren = freshSourceBeforeUpdate.children.filter(
            (c) => c.id !== itemId
          );
          useFolderStore.getState().updateFolderChildren(sourceParentId, updatedSourceChildren);
        }

        // Update dest folder's children (add item)
        const freshDest = getDestFolder();
        if (movedItem && freshDest) {
          const updatedDestChildren = [
            ...freshDest.children,
            { ...movedItem, modifiedAt: Date.now() },
          ];
          useFolderStore.getState().updateFolderChildren(destParentId, updatedDestChildren);
        }

        // Persist the new sequence numbers so subsequent operations use the correct values
        useFolderStore.getState().updateFolderSequence(destParentId, moveResult.destSequenceNumber);
        useFolderStore
          .getState()
          .updateFolderSequence(sourceParentId, moveResult.sourceSequenceNumber);

        setState({ isLoading: false, error: null });
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to move';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  /**
   * Move multiple files/folders to a destination in a single batch.
   *
   * Uses add-before-remove pattern. Publishes IPNS once for the destination
   * and once for the source (2 total), regardless of how many items are moved.
   *
   * @param items - Array of { id, type } to move
   * @param sourceParentId - Current parent folder ID (all items must share the same parent)
   * @param destParentId - Destination parent folder ID
   */
  const handleMoveItems = useCallback(
    async (
      items: Array<{ id: string; type: 'file' | 'folder' }>,
      sourceParentId: string,
      destParentId: string
    ): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const getSourceFolder = () => {
          const freshState = useFolderStore.getState();
          return sourceParentId === 'root'
            ? getRootFolderState(useVaultStore.getState(), freshState.folders)
            : freshState.folders[sourceParentId];
        };
        const getDestFolder = () => {
          const freshState = useFolderStore.getState();
          return destParentId === 'root'
            ? getRootFolderState(useVaultStore.getState(), freshState.folders)
            : freshState.folders[destParentId];
        };

        const sourceFolder = getSourceFolder();
        const destFolder = getDestFolder();

        if (!sourceFolder || !destFolder) {
          throw new Error('Source or destination folder not found');
        }

        const itemIds = new Set(items.map((i) => i.id));
        const now = Date.now();

        // Validate batch move preconditions against current folder state.
        // Must be called before each attempt (initial + retry after resync)
        // because concurrent changes may introduce name collisions or depth violations.
        const validateBatchMove = () => {
          const currentSource = getSourceFolder();
          const currentDest = getDestFolder();
          if (!currentSource || !currentDest) {
            throw new Error('Source or destination folder not found');
          }

          const currentMovedChildren = currentSource.children.filter((c) => itemIds.has(c.id));
          if (currentMovedChildren.length !== itemIds.size) {
            throw new Error(
              'One or more selected items no longer exist. Please refresh and retry.'
            );
          }
          const batchNames = new Set<string>();
          for (const child of currentMovedChildren) {
            // Intra-batch duplicate name check
            if (batchNames.has(child.name)) {
              throw new Error(`Multiple selected items share the name "${child.name}"`);
            }
            batchNames.add(child.name);

            // Name collision check against destination
            const nameExists = currentDest.children.some((c) => c.name === child.name);
            if (nameExists) {
              throw new Error(`An item named "${child.name}" already exists in the destination`);
            }

            if (child.type === 'folder') {
              // Prevent moving folder into itself or descendant
              const folders = useFolderStore.getState().folders;
              if (folderService.isDescendantOf(currentDest.id, child.id, folders)) {
                throw new Error(`Cannot move "${child.name}" into itself or its subfolder`);
              }

              // Depth limit check
              const destDepth = folderService.getDepth(currentDest.id, folders);
              const subtreeDepth = folderService.calculateSubtreeDepth(child.id, folders);
              if (destDepth + 1 + subtreeDepth > MAX_FOLDER_DEPTH) {
                throw new Error(
                  `Cannot move "${child.name}": would exceed maximum folder depth of ${MAX_FOLDER_DEPTH}`
                );
              }
            }
          }
        };

        validateBatchMove();

        const performBatchMove = async (): Promise<{
          destSeq: bigint;
          sourceSeq: bigint;
          destChildren: FolderNode['children'];
          sourceChildren: FolderNode['children'];
        }> => {
          const freshSource = getSourceFolder();
          const freshDest = getDestFolder();
          if (!freshSource || !freshDest) throw new Error('Source or destination folder not found');

          // Rebuild moved children from fresh source state
          const freshMoved = freshSource.children.filter((c) => itemIds.has(c.id));
          if (freshMoved.length !== itemIds.size) {
            throw new Error(
              'One or more selected items no longer exist. Please refresh and retry.'
            );
          }

          // ADD all to destination FIRST (add-before-remove pattern)
          const destChildren = [
            ...freshDest.children,
            ...freshMoved.map((c) => ({ ...c, modifiedAt: now })),
          ];

          const { newSequenceNumber: destSeq } = await folderService.updateFolderMetadata({
            folderId: freshDest.id,
            children: destChildren,
            folderKey: freshDest.folderKey,
            ipnsPrivateKey: freshDest.ipnsPrivateKey,
            ipnsName: freshDest.ipnsName,
            sequenceNumber: freshDest.sequenceNumber,
          });

          // REMOVE all from source AFTER destination confirmed
          const sourceChildren = freshSource.children.filter((c) => !itemIds.has(c.id));

          const { newSequenceNumber: sourceSeq } = await folderService.updateFolderMetadata({
            folderId: freshSource.id,
            children: sourceChildren,
            folderKey: freshSource.folderKey,
            ipnsPrivateKey: freshSource.ipnsPrivateKey,
            ipnsName: freshSource.ipnsName,
            // Re-read sequence in case source === dest parent was updated above
            sequenceNumber: freshSource.id === freshDest.id ? destSeq : freshSource.sequenceNumber,
          });

          return { destSeq, sourceSeq, destChildren, sourceChildren };
        };

        const result = await withConflictRetry(
          performBatchMove,
          async () => {
            await Promise.all([
              resyncFolder(sourceFolder.ipnsName, sourceFolder.id),
              sourceFolder.id !== destFolder.id
                ? resyncFolder(destFolder.ipnsName, destFolder.id)
                : Promise.resolve(),
            ]);
          },
          validateBatchMove
        );

        // Update local state
        const store = useFolderStore.getState();
        store.updateFolderChildren(sourceParentId, result.sourceChildren);
        store.updateFolderChildren(destParentId, result.destChildren);
        store.updateFolderSequence(destParentId, result.destSeq);
        store.updateFolderSequence(sourceParentId, result.sourceSeq);

        for (const item of items) {
          if (item.type === 'folder') {
            const movedFolder = useFolderStore.getState().folders[item.id];
            if (movedFolder) {
              store.setFolder({ ...movedFolder, parentId: destParentId });
            }
          }
        }

        setState({ isLoading: false, error: null });
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to move items';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  /**
   * Delete a file or folder.
   *
   * @param itemId - ID of item to delete
   * @param itemType - 'file' or 'folder'
   * @param parentId - Parent folder ID
   */
  const handleDelete = useCallback(
    async (itemId: string, itemType: 'file' | 'folder', parentId: string): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const getParentFolder = () => {
          const freshState = useFolderStore.getState();
          return parentId === 'root'
            ? getRootFolderState(useVaultStore.getState(), freshState.folders)
            : freshState.folders[parentId];
        };

        const parentFolder = getParentFolder();
        if (!parentFolder) throw new Error('Parent folder not found');

        const performDelete = async (): Promise<{
          newSequenceNumber: bigint;
          removedChild: FolderChild;
        }> => {
          const freshParent = getParentFolder();
          if (!freshParent) throw new Error('Parent folder not found');
          if (itemType === 'folder') {
            const folders = useFolderStore.getState().folders;
            const { newSequenceNumber, removedChild } = await folderService.deleteFolder({
              folderId: itemId,
              parentFolderState: freshParent,
              getFolderState: (id) => folders[id],
            });
            return { newSequenceNumber, removedChild };
          } else {
            const { newSequenceNumber, removedChild } = await folderService.deleteFileFromFolder({
              fileId: itemId,
              parentFolderState: freshParent,
            });
            return { newSequenceNumber, removedChild };
          }
        };

        const deleteResult = await withConflictRetry(performDelete, () =>
          resyncFolder(parentFolder.ipnsName, parentFolder.id)
        );

        if (itemType === 'folder') {
          // Remove folder and all loaded descendants from local state
          const store = useFolderStore.getState();
          const removeRecursive = (folderId: string) => {
            const node = store.folders[folderId];
            if (node) {
              for (const child of node.children) {
                if (child.type === 'folder') removeRecursive(child.id);
              }
            }
            store.removeFolder(folderId);
          };
          removeRecursive(itemId);
        }

        // Update parent's children (remove item) using fresh state
        const freshParent = getParentFolder();
        if (freshParent) {
          const updatedChildren = freshParent.children.filter((c) => c.id !== itemId);
          useFolderStore.getState().updateFolderChildren(parentId, updatedChildren);
        }

        // Persist the new sequence number so subsequent operations use the correct value
        useFolderStore.getState().updateFolderSequence(parentId, deleteResult.newSequenceNumber);

        // Fire-and-forget: add deleted item to recycle bin (CIDs stay pinned for recovery)
        const auth = useAuthStore.getState();
        if (auth.vaultKeypair) {
          void addManyToBin({
            items: [deleteResult.removedChild],
            parentIpnsName: parentFolder.ipnsName,
            parentPath: buildFolderPath(parentId),
            userPublicKey: auth.vaultKeypair.publicKey,
            userPrivateKey: auth.vaultKeypair.privateKey,
          }).catch(() => {
            console.error('[Delete] Failed to add to bin (non-blocking)');
          });
        }

        setState({ isLoading: false, error: null });
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to delete';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  /**
   * Delete multiple files/folders in a single IPNS publish.
   *
   * Removes all items from parent's children array, collects CIDs to unpin,
   * then publishes metadata and IPNS once for the entire batch.
   *
   * @param items - Array of { id, type } to delete
   * @param parentId - Parent folder ID (all items must share the same parent)
   */
  const handleDeleteItems = useCallback(
    async (
      items: Array<{ id: string; type: 'file' | 'folder' }>,
      parentId: string
    ): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const getParentFolder = () => {
          const freshState = useFolderStore.getState();
          return parentId === 'root'
            ? getRootFolderState(useVaultStore.getState(), freshState.folders)
            : freshState.folders[parentId];
        };

        const parentFolder = getParentFolder();
        if (!parentFolder) throw new Error('Parent folder not found');

        const itemIds = new Set(items.map((i) => i.id));

        // Collect nested folder IDs to remove from store
        // In v2, file children are FilePointers (no inline CID). File IPNS/TEE
        // enrollments will expire naturally (24h IPNS lifetime). Phase 14 adds cleanup.
        const folderIdsToRemove: string[] = [];

        const collectFolderIds = (folderId: string) => {
          folderIdsToRemove.push(folderId);
          const folders = useFolderStore.getState().folders;
          const folder = folders[folderId];
          if (!folder) return;
          for (const child of folder.children) {
            if (child.type === 'folder') {
              collectFolderIds(child.id);
            }
          }
        };

        for (const item of items) {
          if (item.type === 'folder') {
            collectFolderIds(item.id);
          }
        }

        // Snapshot the items to be removed before batch delete
        // (needed for addToBin after successful deletion)
        let removedChildren: FolderChild[] = [];

        const performBatchDelete = async (): Promise<{
          updatedChildren: typeof parentFolder.children;
          newSequenceNumber: bigint;
        }> => {
          const freshParent = getParentFolder();
          if (!freshParent) throw new Error('Parent folder not found');

          // Capture removed children before filtering
          removedChildren = freshParent.children.filter((c) => itemIds.has(c.id));

          // Remove all items from parent's children in one pass
          const updatedChildren = freshParent.children.filter((c) => !itemIds.has(c.id));

          // Single IPNS publish for the entire batch
          const { newSequenceNumber } = await folderService.updateFolderMetadata({
            folderId: freshParent.id,
            children: updatedChildren,
            folderKey: freshParent.folderKey,
            ipnsPrivateKey: freshParent.ipnsPrivateKey,
            ipnsName: freshParent.ipnsName,
            sequenceNumber: freshParent.sequenceNumber,
          });

          return { updatedChildren, newSequenceNumber };
        };

        const { updatedChildren, newSequenceNumber } = await withConflictRetry(
          performBatchDelete,
          () => resyncFolder(parentFolder.ipnsName, parentFolder.id)
        );

        // Update local state -- remove all nested folders from store
        const store = useFolderStore.getState();
        store.updateFolderChildren(parentId, updatedChildren);
        store.updateFolderSequence(parentId, newSequenceNumber);
        for (const folderId of folderIdsToRemove) {
          store.removeFolder(folderId);
        }

        // Fire-and-forget: add all deleted items to recycle bin (single IPNS publish)
        const auth = useAuthStore.getState();
        if (auth.vaultKeypair && removedChildren.length > 0) {
          const parentPath = buildFolderPath(parentId);
          void addManyToBin({
            items: removedChildren,
            parentIpnsName: parentFolder.ipnsName,
            parentPath,
            userPublicKey: auth.vaultKeypair.publicKey,
            userPrivateKey: auth.vaultKeypair.privateKey,
          }).catch(() => {
            console.error('[Delete] Failed to add batch to bin (non-blocking)');
          });
        }

        setState({ isLoading: false, error: null });
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to delete items';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  return {
    ...state,
    createFolder: handleCreate,
    renameItem: handleRename,
    moveItem: handleMove,
    moveItems: handleMoveItems,
    deleteItem: handleDelete,
    deleteItems: handleDeleteItems,
  };
}
