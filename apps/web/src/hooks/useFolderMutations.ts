import { useState, useCallback } from 'react';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useAuthStore } from '../stores/auth.store';
import { unpinFromIpfs } from '../lib/api/ipfs';
import * as folderService from '../services/folder.service';
import { reWrapForRecipients } from '../services/share.service';
import type { FolderNode } from '../stores/folder.store';
import type { FolderEntry } from '@cipherbox/crypto';
import { MAX_FOLDER_DEPTH, getRootFolderState } from './folder-helpers';
import type { FolderOperationState } from './folder-helpers';

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

        // Add to parent's children
        const newChildren = [...parentFolder.children, folder];

        // Update parent folder metadata and publish IPNS
        await folderService.updateFolderMetadata({
          folderId: parentFolder.id,
          children: newChildren,
          folderKey: parentFolder.folderKey,
          ipnsPrivateKey: parentFolder.ipnsPrivateKey,
          ipnsName: parentFolder.ipnsName,
          sequenceNumber: parentFolder.sequenceNumber,
        });

        // First publish for the new folder's own IPNS record with TEE-encrypted key
        // This sends encryptedIpnsPrivateKey to backend for TEE republish enrollment
        await folderService.updateFolderMetadata({
          folderId: folder.id,
          children: [],
          folderKey,
          ipnsPrivateKey,
          ipnsName: folder.ipnsName,
          sequenceNumber: 0n,
          encryptedIpnsPrivateKey,
          keyEpoch,
        });

        // Update local state - add new folder to tree
        useFolderStore.getState().updateFolderChildren(parentFolder.id, newChildren);

        // Also add the new folder node to the store (with its decrypted keys)
        const newFolderNode: FolderNode = {
          id: folder.id,
          name: folder.name,
          ipnsName: folder.ipnsName,
          parentId: parentFolder.id,
          children: [],
          isLoaded: true,
          isLoading: false,
          sequenceNumber: 0n,
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
        const folders = useFolderStore.getState().folders;
        const vault = useVaultStore.getState();

        // Get parent folder state
        const parentFolder =
          parentId === 'root' ? getRootFolderState(vault, folders) : folders[parentId];

        if (!parentFolder) throw new Error('Parent folder not found');

        if (itemType === 'folder') {
          await folderService.renameFolder({
            folderId: itemId,
            newName,
            parentFolderState: parentFolder,
          });

          // Update local folder state name
          useFolderStore.getState().updateFolderName(itemId, newName);
        } else {
          await folderService.renameFile({
            fileId: itemId,
            newName,
            parentFolderState: parentFolder,
          });
        }

        // Update parent's children with new name
        const updatedChildren = parentFolder.children.map((child) => {
          if (child.id === itemId) {
            return { ...child, name: newName, modifiedAt: Date.now() };
          }
          return child;
        });
        useFolderStore.getState().updateFolderChildren(parentId, updatedChildren);

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
        const folders = useFolderStore.getState().folders;
        const vault = useVaultStore.getState();

        // Get source and destination folder states
        const sourceFolder =
          sourceParentId === 'root' ? getRootFolderState(vault, folders) : folders[sourceParentId];

        const destFolder =
          destParentId === 'root' ? getRootFolderState(vault, folders) : folders[destParentId];

        if (!sourceFolder || !destFolder) {
          throw new Error('Source or destination folder not found');
        }

        if (itemType === 'folder') {
          await folderService.moveFolder({
            folderId: itemId,
            sourceFolderState: sourceFolder,
            destFolderState: destFolder,
            folders,
          });

          // Update the moved folder's parentId in local state
          const movedFolder = folders[itemId];
          if (movedFolder) {
            useFolderStore.getState().setFolder({
              ...movedFolder,
              parentId: destParentId,
            });
          }
        } else {
          await folderService.moveFile({
            fileId: itemId,
            sourceFolderState: sourceFolder,
            destFolderState: destFolder,
          });
        }

        // Update source folder's children (remove item)
        const updatedSourceChildren = sourceFolder.children.filter((c) => c.id !== itemId);
        useFolderStore.getState().updateFolderChildren(sourceParentId, updatedSourceChildren);

        // Update dest folder's children (add item)
        const movedItem = sourceFolder.children.find((c) => c.id === itemId);
        if (movedItem) {
          const updatedDestChildren = [
            ...destFolder.children,
            { ...movedItem, modifiedAt: Date.now() },
          ];
          useFolderStore.getState().updateFolderChildren(destParentId, updatedDestChildren);
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
        const folders = useFolderStore.getState().folders;
        const vault = useVaultStore.getState();

        const sourceFolder =
          sourceParentId === 'root' ? getRootFolderState(vault, folders) : folders[sourceParentId];
        const destFolder =
          destParentId === 'root' ? getRootFolderState(vault, folders) : folders[destParentId];

        if (!sourceFolder || !destFolder) {
          throw new Error('Source or destination folder not found');
        }

        const itemIds = new Set(items.map((i) => i.id));
        const movedChildren = sourceFolder.children.filter((c) => itemIds.has(c.id));
        const now = Date.now();

        // Validate all items
        const batchNames = new Set<string>();
        for (const child of movedChildren) {
          // Intra-batch duplicate name check
          if (batchNames.has(child.name)) {
            throw new Error(`Multiple selected items share the name "${child.name}"`);
          }
          batchNames.add(child.name);

          // Name collision check against destination
          const nameExists = destFolder.children.some((c) => c.name === child.name);
          if (nameExists) {
            throw new Error(`An item named "${child.name}" already exists in the destination`);
          }

          if (child.type === 'folder') {
            // Prevent moving folder into itself or descendant
            if (folderService.isDescendantOf(destFolder.id, child.id, folders)) {
              throw new Error(`Cannot move "${child.name}" into itself or its subfolder`);
            }

            // Depth limit check
            const destDepth = folderService.getDepth(destFolder.id, folders);
            const subtreeDepth = folderService.calculateSubtreeDepth(child.id, folders);
            if (destDepth + 1 + subtreeDepth > MAX_FOLDER_DEPTH) {
              throw new Error(
                `Cannot move "${child.name}": would exceed maximum folder depth of ${MAX_FOLDER_DEPTH}`
              );
            }
          }
        }

        // ADD all to destination FIRST (add-before-remove pattern)
        const destChildren = [
          ...destFolder.children,
          ...movedChildren.map((c) => ({ ...c, modifiedAt: now })),
        ];

        const { newSequenceNumber: destSeq } = await folderService.updateFolderMetadata({
          folderId: destFolder.id,
          children: destChildren,
          folderKey: destFolder.folderKey,
          ipnsPrivateKey: destFolder.ipnsPrivateKey,
          ipnsName: destFolder.ipnsName,
          sequenceNumber: destFolder.sequenceNumber,
        });

        // REMOVE all from source AFTER destination confirmed
        const sourceChildren = sourceFolder.children.filter((c) => !itemIds.has(c.id));

        const { newSequenceNumber: sourceSeq } = await folderService.updateFolderMetadata({
          folderId: sourceFolder.id,
          children: sourceChildren,
          folderKey: sourceFolder.folderKey,
          ipnsPrivateKey: sourceFolder.ipnsPrivateKey,
          ipnsName: sourceFolder.ipnsName,
          // Re-read sequence in case source === dest parent was updated above
          sequenceNumber: sourceFolder.id === destFolder.id ? destSeq : sourceFolder.sequenceNumber,
        });

        // Update local state
        const store = useFolderStore.getState();
        store.updateFolderChildren(sourceParentId, sourceChildren);
        store.updateFolderChildren(destParentId, destChildren);
        store.updateFolderSequence(destParentId, destSeq);
        store.updateFolderSequence(sourceParentId, sourceSeq);

        for (const item of items) {
          if (item.type === 'folder') {
            const movedFolder = folders[item.id];
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
        const folders = useFolderStore.getState().folders;
        const vault = useVaultStore.getState();

        // Get parent folder state
        const parentFolder =
          parentId === 'root' ? getRootFolderState(vault, folders) : folders[parentId];

        if (!parentFolder) throw new Error('Parent folder not found');

        if (itemType === 'folder') {
          await folderService.deleteFolder({
            folderId: itemId,
            parentFolderState: parentFolder,
            getFolderState: (id) => folders[id],
            unpinCid: unpinFromIpfs,
          });

          // Remove folder from local state
          useFolderStore.getState().removeFolder(itemId);
        } else {
          await folderService.deleteFileFromFolder({
            fileId: itemId,
            parentFolderState: parentFolder,
          });
        }

        // Update parent's children (remove item)
        const updatedChildren = parentFolder.children.filter((c) => c.id !== itemId);
        useFolderStore.getState().updateFolderChildren(parentId, updatedChildren);

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
        const folders = useFolderStore.getState().folders;
        const vault = useVaultStore.getState();

        const parentFolder =
          parentId === 'root' ? getRootFolderState(vault, folders) : folders[parentId];

        if (!parentFolder) throw new Error('Parent folder not found');

        const itemIds = new Set(items.map((i) => i.id));

        // Collect nested folder IDs to remove from store
        // In v2, file children are FilePointers (no inline CID). File IPNS/TEE
        // enrollments will expire naturally (24h IPNS lifetime). Phase 14 adds cleanup.
        const folderIdsToRemove: string[] = [];

        const collectFolderIds = (folderId: string) => {
          folderIdsToRemove.push(folderId);
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

        // Remove all items from parent's children in one pass
        const updatedChildren = parentFolder.children.filter((c) => !itemIds.has(c.id));

        // Single IPNS publish for the entire batch
        await folderService.updateFolderMetadata({
          folderId: parentFolder.id,
          children: updatedChildren,
          folderKey: parentFolder.folderKey,
          ipnsPrivateKey: parentFolder.ipnsPrivateKey,
          ipnsName: parentFolder.ipnsName,
          sequenceNumber: parentFolder.sequenceNumber,
        });

        // Update local state -- remove all nested folders from store
        const store = useFolderStore.getState();
        store.updateFolderChildren(parentId, updatedChildren);
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
