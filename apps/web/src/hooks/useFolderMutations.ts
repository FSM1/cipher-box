import { useState, useCallback } from 'react';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import type { FolderNode } from '../stores/folder.store';
import { getSdkClient } from '../lib/sdk-provider';
import { BinNotLoadedError, getDepth, isDescendantOf, calculateSubtreeDepth } from '@cipherbox/sdk';
import { useVaultSettingsStore } from '../stores/vault-settings.store';
import { MAX_FOLDER_DEPTH, getRootFolderState } from './folder-helpers';
import type { FolderOperationState } from './folder-helpers';
import { runWithFailureUx } from './useMutationFailureUx';

/**
 * Delete an item using the user's preferred delete behavior.
 * 'permanent' skips the bin; 'bin' soft-deletes with fallback to hard delete
 * when the bin is not loaded.
 */
async function deleteWithBehavior(
  client: ReturnType<typeof getSdkClient>,
  ipnsName: string,
  itemId: string,
  parentPath: string
): Promise<void> {
  const { deleteBehavior } = useVaultSettingsStore.getState().settings;

  await runWithFailureUx(async () => {
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
  });
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
 * Collect every already-loaded descendant FolderNode id whose parentId chain
 * reaches `rootId` (breadth-first over the store's parentId links).
 *
 * Used to purge a deleted folder's subtree from the store so no orphaned/stale
 * descendant entry survives to be hit by useFolderNavigation's `isLoaded` fast
 * path. Identity stays ipnsName-keyed: this walks the store tree by `parentId`
 * only and never re-keys to Node.id (the read-plane is intentionally
 * ipnsName-keyed). Returns descendant ids only — not `rootId` itself.
 */
function collectDescendantFolderIds(folders: Record<string, FolderNode>, rootId: string): string[] {
  const descendants: string[] = [];
  const queue: string[] = [rootId];
  const allFolders = Object.values(folders);
  while (queue.length > 0) {
    const currentId = queue.shift() as string;
    for (const folder of allFolders) {
      if (folder.parentId === currentId && !descendants.includes(folder.id)) {
        descendants.push(folder.id);
        queue.push(folder.id);
      }
    }
  }
  return descendants;
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
        const parentDepth = getDepth(parentId, folders);
        if (parentDepth >= MAX_FOLDER_DEPTH) {
          throw new Error(`Cannot create folder: maximum depth of ${MAX_FOLDER_DEPTH} exceeded`);
        }

        // Resolve parent folder
        const actualParentId = parentId ?? 'root';
        const parentFolder = getParentFolder(actualParentId);
        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        // Create folder via SDK (handles key gen, metadata update, IPNS publish).
        // Wrapped in runWithFailureUx so a stale local sequence (ReconcileStaleError,
        // SC#3/D-04) retries with bounded backoff instead of failing closed on the
        // first attempt -- matching rename/move/delete's existing retry wiring.
        const client = getSdkClient();
        let result!: Awaited<ReturnType<typeof client.createFolder>>;
        await runWithFailureUx(async () => {
          result = await client.createFolder(parentFolder.ipnsName, name);
        });

        // SDK emits folder:updated -> store subscription updates parent's children
        // But we also need to add the new folder as a store node so navigation works.
        // Keyed by ipnsName (not the write-body UUID result.id) to match
        // useFolderNavigation's navigateTo, which keys/looks up every FolderNode by
        // ipnsName (route param `/files/:folderId` is always an ipnsName). Keying by
        // UUID here created a second, orphaned store entry with the same ipnsName as
        // the one navigateTo later creates on first navigation into this folder;
        // folder.store's SDK event subscription (which resolves the target entry via
        // `f.ipnsName === event.ipnsName`) could then match the orphaned UUID-keyed
        // entry instead of the one FileBrowser actually reads from, silently dropping
        // subsequent 'folder:updated' children updates (e.g. a grandchild create).
        const newFolderNode: FolderNode = {
          id: result.ipnsName,
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

        // Post-create re-wrapping is handled by CipherBoxClient.createFolder()
        // internally (the legacy share-callback re-wrap config was removed —
        // encrypted-key grant refs replace the per-recipient key fan-out).

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

        // Rename via SDK (handles metadata update, IPNS publish)
        const client = getSdkClient();
        await runWithFailureUx(() => client.renameItem(parentFolder.ipnsName, itemId, newName));

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

        // Move via SDK (handles add-before-remove, both IPNS publishes)
        const client = getSdkClient();
        await runWithFailureUx(() =>
          client.moveItem(sourceFolder.ipnsName, destFolder.ipnsName, itemId)
        );

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

        for (const item of items) {
          if (item.type === 'folder') {
            // Prevent moving folder into itself or descendant
            if (isDescendantOf(destFolder.id, item.id, folders)) {
              throw new Error(`Cannot move folder into itself or its subfolder`);
            }

            // Depth limit check
            const destDepth = getDepth(destFolder.id, folders);
            const subtreeDepth = calculateSubtreeDepth(item.id, folders);
            if (destDepth + 1 + subtreeDepth > MAX_FOLDER_DEPTH) {
              throw new Error(
                `Cannot move: would exceed maximum folder depth of ${MAX_FOLDER_DEPTH}`
              );
            }
          }
        }

        // Name collision check against destination
        const movedNames = items
          .map((i) => {
            const ref = sourceFolder.children.find((c) => c.ipnsName === i.id);
            return ref?.name;
          })
          .filter((n): n is string => n !== undefined);
        for (const name of movedNames) {
          const nameExists = destFolder.children.some((c) => c.name === name);
          if (nameExists) {
            throw new Error(`An item named "${name}" already exists in the destination`);
          }
        }

        // Move each item via SDK
        const client = getSdkClient();
        for (const item of items) {
          await runWithFailureUx(() =>
            client.moveItem(sourceFolder.ipnsName, destFolder.ipnsName, item.id)
          );

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

        const client = getSdkClient();
        const parentPath = buildFolderPath(parentId);

        // Snapshot the loaded subtree BEFORE the SDK delete (mirrors the batch
        // path): store events fired during deleteWithBehavior could prune
        // descendant FolderNodes, and the post-delete walk would then miss them.
        const preDeleteFolders = itemType === 'folder' ? useFolderStore.getState().folders : null;

        await deleteWithBehavior(client, parentFolder.ipnsName, itemId, parentPath);

        // SDK emits folder:updated -> store subscription updates children.
        // Remove the deleted folder AND every already-loaded descendant
        // FolderNode (walk parentId links) so no orphaned/stale entry survives
        // to be hit by useFolderNavigation's isLoaded fast path.
        if (itemType === 'folder' && preDeleteFolders) {
          const store = useFolderStore.getState();
          for (const descendantId of collectDescendantFolderIds(preDeleteFolders, itemId)) {
            store.removeFolder(descendantId);
          }
          store.removeFolder(itemId);
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

        // Snapshot the loaded tree BEFORE any SDK delete so each folder's
        // parentId walk sees its full loaded subtree (store events during the
        // deletes could prune descendants first).
        const preDeleteFolders = useFolderStore.getState().folders;

        // Delete each item via SDK (sequentially to maintain consistency) and
        // purge its subtree from the store IMMEDIATELY after its own success, so
        // a later item throwing does not strand already-deleted folders as stale
        // entries (which useFolderNavigation's isLoaded fast path could match).
        const client = getSdkClient();
        const parentPath = buildFolderPath(parentId);
        const store = useFolderStore.getState();

        for (const item of items) {
          await deleteWithBehavior(client, parentFolder.ipnsName, item.id, parentPath);
          if (item.type === 'folder') {
            for (const descendantId of collectDescendantFolderIds(preDeleteFolders, item.id)) {
              store.removeFolder(descendantId);
            }
            store.removeFolder(item.id);
          }
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
