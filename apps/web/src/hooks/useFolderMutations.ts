import { useState, useCallback } from 'react';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import * as folderService from '../services/folder.service';
import type { FolderNode } from '../stores/folder.store';
import { getSdkClient, ensureFolderRegistered } from '../lib/sdk-provider';
import { BinNotLoadedError } from '@cipherbox/sdk';
import { useVaultSettingsStore } from '../stores/vault-settings.store';
import { MAX_FOLDER_DEPTH, getRootFolderState } from './folder-helpers';
import type { FolderOperationState } from './folder-helpers';

/**
 * Delete an item using the user's preferred delete behavior.
 * 'permanent' skips the bin; 'bin' soft-deletes with fallback to hard delete
 * when the bin is not loaded.
 */
async function deleteWithBehavior(
  client: ReturnType<typeof getSdkClient>,
  ipnsName: string,
  itemId: string,
  parentPath: string,
): Promise<void> {
  const { deleteBehavior } = useVaultSettingsStore.getState().settings;

  if (deleteBehavior === 'permanent') {
    await client.deleteItem(ipnsName, itemId);
  } else {
    try {
      await client.deleteToBin(ipnsName, itemId, parentPath);
    } catch (binErr) {
      if (binErr instanceof BinNotLoadedError) {
        await client.deleteItem(ipnsName, itemId);
      } else {
        throw binErr;
      }
    }
  }
}

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
    // Stop before including the root node (its name is already the "My Vault" prefix)
    if (folder.parentId === null) break;
    parts.unshift(folder.name);
    currentId = folder.parentId;
  }

  return parts.length > 0 ? `My Vault / ${parts.join(' / ')}` : 'My Vault';
}

/**
 * Get the parent folder node from the store, resolving 'root' via vault state.
 */
function getParentFolder(parentId: string): FolderNode | null {
  const freshState = useFolderStore.getState();
  return parentId === 'root'
    ? getRootFolderState(useVaultStore.getState(), freshState.folders)
    : freshState.folders[parentId];
}

/**
 * React hook for folder CRUD operations (create, rename, move, delete).
 *
 * Operations delegate to CipherBoxClient SDK methods. The SDK handles
 * crypto, metadata construction, and IPNS publishing internally. SDK
 * events update the folder store via event subscriptions.
 *
 * The hook manages UI concerns: loading state, error handling, toasts,
 * and store-level coordination (folder node management, share re-wrapping).
 */
export function useFolderMutations() {
  const [state, setState] = useState<FolderOperationState>({
    isLoading: false,
    error: null,
  });

  /**
   * Create a new folder via SDK.
   *
   * @param name - Folder name
   * @param parentId - Parent folder ID (null for root, or folder UUID)
   * @returns Created folder IPNS name and key
   */
  const handleCreate = useCallback(
    async (name: string, parentId: string | null): Promise<{ ipnsName: string }> => {
      setState({ isLoading: true, error: null });
      try {
        const folders = useFolderStore.getState().folders;

        // Validate depth limit before creating (FOLD-03)
        const parentDepth = folderService.getDepth(parentId, folders);
        if (parentDepth >= MAX_FOLDER_DEPTH) {
          throw new Error(`Cannot create folder: maximum depth of ${MAX_FOLDER_DEPTH} exceeded`);
        }

        // Resolve parent folder
        const actualParentId = parentId ?? 'root';
        const parentFolder = getParentFolder(actualParentId);
        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        // Ensure parent is registered in SDK's FolderTree
        ensureFolderRegistered(parentFolder);

        // Create folder via SDK (handles key gen, metadata update, IPNS publish)
        const client = getSdkClient();
        const result = await client.createFolder(parentFolder.ipnsName, name);

        // SDK emits folder:updated -> store subscription updates parent's children
        // But we also need to add the new folder as a store node so navigation works
        const newFolderNode: FolderNode = {
          id: result.id, // UUID from the FolderEntry in parent's children
          name,
          ipnsName: result.ipnsName,
          parentId: actualParentId,
          children: [],
          isLoaded: true,
          isLoading: false,
          sequenceNumber: 1n,
          folderKey: result.folderKey,
          ipnsPrivateKey: result.ipnsPrivateKey,
        };
        useFolderStore.getState().setFolder(newFolderNode);

        // Post-create re-wrapping is handled by the SDK's shareCallbacks.
        // The CipherBoxClient.createFolder() calls reWrapNewItems() internally.

        setState({ isLoading: false, error: null });
        return { ipnsName: result.ipnsName };
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to create folder';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  /**
   * Rename a file or folder via SDK.
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
        const parentFolder = getParentFolder(parentId);
        if (!parentFolder) throw new Error('Parent folder not found');

        // Ensure parent is registered in SDK
        ensureFolderRegistered(parentFolder);

        // Rename via SDK (handles metadata update, IPNS publish)
        const client = getSdkClient();
        await client.renameItem(parentFolder.ipnsName, itemId, newName);

        // SDK emits folder:updated -> store subscription updates children
        // Also update the folder name in the store if renaming a folder
        if (itemType === 'folder') {
          useFolderStore.getState().updateFolderName(itemId, newName);
        }

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
   * Move a file or folder via SDK.
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
        const sourceFolder = getParentFolder(sourceParentId);
        const destFolder = getParentFolder(destParentId);
        if (!sourceFolder || !destFolder) {
          throw new Error('Source or destination folder not found');
        }

        // Ensure both folders are registered in SDK
        ensureFolderRegistered(sourceFolder);
        ensureFolderRegistered(destFolder);

        // Move via SDK (handles add-before-remove, both IPNS publishes)
        const client = getSdkClient();
        await client.moveItem(sourceFolder.ipnsName, destFolder.ipnsName, itemId);

        // SDK emits folder:updated for both folders -> store subscription updates children
        // Also update parentId for moved folders
        if (itemType === 'folder') {
          const movedFolder = useFolderStore.getState().folders[itemId];
          if (movedFolder) {
            useFolderStore.getState().setFolder({
              ...movedFolder,
              parentId: destParentId,
            });
          }
        }

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
   * Move multiple files/folders to a destination.
   *
   * Uses SDK moveItem for each item sequentially to preserve event ordering.
   *
   * @param items - Array of { id, type } to move
   * @param sourceParentId - Current parent folder ID
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
        const sourceFolder = getParentFolder(sourceParentId);
        const destFolder = getParentFolder(destParentId);
        if (!sourceFolder || !destFolder) {
          throw new Error('Source or destination folder not found');
        }

        // Validate batch move preconditions
        const folders = useFolderStore.getState().folders;
        const itemIds = new Set(items.map((i) => i.id));

        for (const item of items) {
          if (item.type === 'folder') {
            // Prevent moving folder into itself or descendant
            if (folderService.isDescendantOf(destFolder.id, item.id, folders)) {
              throw new Error(`Cannot move folder into itself or its subfolder`);
            }

            // Depth limit check
            const destDepth = folderService.getDepth(destFolder.id, folders);
            const subtreeDepth = folderService.calculateSubtreeDepth(item.id, folders);
            if (destDepth + 1 + subtreeDepth > MAX_FOLDER_DEPTH) {
              throw new Error(
                `Cannot move: would exceed maximum folder depth of ${MAX_FOLDER_DEPTH}`
              );
            }
          }
        }

        // Name collision check against destination
        const movedChildren = sourceFolder.children.filter((c) => itemIds.has(c.id));
        for (const child of movedChildren) {
          const nameExists = destFolder.children.some((c) => c.name === child.name);
          if (nameExists) {
            throw new Error(`An item named "${child.name}" already exists in the destination`);
          }
        }

        // Ensure both folders are registered in SDK
        ensureFolderRegistered(sourceFolder);
        ensureFolderRegistered(destFolder);

        // Move each item via SDK
        const client = getSdkClient();
        for (const item of items) {
          await client.moveItem(sourceFolder.ipnsName, destFolder.ipnsName, item.id);

          if (item.type === 'folder') {
            const movedFolder = useFolderStore.getState().folders[item.id];
            if (movedFolder) {
              useFolderStore.getState().setFolder({ ...movedFolder, parentId: destParentId });
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
   * Delete a file or folder via SDK.
   *
   * Uses deleteToBin for soft-delete (moves to recycle bin) when the SDK's
   * bin state is loaded, otherwise falls back to deleteItem (hard metadata delete)
   * with a fire-and-forget bin service call.
   *
   * @param itemId - ID of item to delete
   * @param itemType - 'file' or 'folder'
   * @param parentId - Parent folder ID
   */
  const handleDelete = useCallback(
    async (itemId: string, itemType: 'file' | 'folder', parentId: string): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const parentFolder = getParentFolder(parentId);
        if (!parentFolder) throw new Error('Parent folder not found');

        // Ensure parent is registered in SDK
        ensureFolderRegistered(parentFolder);

        const client = getSdkClient();
        const parentPath = buildFolderPath(parentId);

        await deleteWithBehavior(client, parentFolder.ipnsName, itemId, parentPath);

        // SDK emits folder:updated -> store subscription updates children
        // Remove folder subtree from store if deleting a folder
        if (itemType === 'folder') {
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
   * Delete multiple files/folders.
   *
   * @param items - Array of { id, type } to delete
   * @param parentId - Parent folder ID
   */
  const handleDeleteItems = useCallback(
    async (
      items: Array<{ id: string; type: 'file' | 'folder' }>,
      parentId: string
    ): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const parentFolder = getParentFolder(parentId);
        if (!parentFolder) throw new Error('Parent folder not found');

        // Ensure parent is registered in SDK
        ensureFolderRegistered(parentFolder);

        // Collect nested folder IDs to remove from store
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

        // Delete each item via SDK (sequentially to maintain consistency)
        const client = getSdkClient();
        const parentPath = buildFolderPath(parentId);

        for (const item of items) {
          // Re-register parent between deletes since SDK updates its internal state
          const freshParent = getParentFolder(parentId);
          if (freshParent) ensureFolderRegistered(freshParent);

          await deleteWithBehavior(client, parentFolder.ipnsName, item.id, parentPath);
        }

        // Remove nested folders from store
        const store = useFolderStore.getState();
        for (const folderId of folderIdsToRemove) {
          store.removeFolder(folderId);
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
