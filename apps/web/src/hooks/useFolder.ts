import { useState, useCallback } from 'react';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useAuthStore } from '../stores/auth.store';
import { unpinFromIpfs } from '../lib/api/ipfs';
import * as folderService from '../services/folder.service';
import type { FolderNode } from '../stores/folder.store';
import type { FolderEntry, FileEntry } from '@cipherbox/crypto';

/** Maximum folder nesting depth per FOLD-03 */
const MAX_FOLDER_DEPTH = 20;

/**
 * State for folder operations.
 */
type FolderOperationState = {
  isLoading: boolean;
  error: string | null;
};

/**
 * Get the root folder state from vault and folder stores.
 * Root folder uses vault keys directly.
 */
function getRootFolderState(
  vaultStore: ReturnType<typeof useVaultStore.getState>,
  folders: Record<string, FolderNode>
): FolderNode | null {
  if (!vaultStore.rootFolderKey || !vaultStore.rootIpnsKeypair || !vaultStore.rootIpnsName) {
    return null;
  }

  // If we have an explicit root folder in the tree, use it
  const existingRoot = folders['root'];
  if (existingRoot) return existingRoot;

  // Otherwise construct from vault state
  return {
    id: 'root',
    name: 'My Vault',
    ipnsName: vaultStore.rootIpnsName,
    parentId: null,
    children: [],
    isLoaded: false,
    isLoading: false,
    sequenceNumber: 0n,
    folderKey: vaultStore.rootFolderKey,
    ipnsPrivateKey: vaultStore.rootIpnsKeypair.privateKey,
  };
}

/**
 * Calculate folder depth by walking up the tree.
 */
function calculateFolderDepth(folderId: string, folders: Record<string, FolderNode>): number {
  return folderService.getDepth(folderId, folders);
}

/**
 * React hook for folder operations with loading/error state.
 *
 * Provides createFolder, renameItem, moveItem, and deleteItem operations
 * that wrap folder.service functions with proper state management.
 *
 * @example
 * ```tsx
 * function FolderActions() {
 *   const { isLoading, error, createFolder, deleteItem } = useFolder();
 *
 *   const handleCreate = async () => {
 *     try {
 *       await createFolder('New Folder', currentFolderId);
 *     } catch (err) {
 *       // Error also in error state
 *     }
 *   };
 *
 *   return (
 *     <div>
 *       {isLoading && <Spinner />}
 *       {error && <ErrorMessage>{error}</ErrorMessage>}
 *       <button onClick={handleCreate}>New Folder</button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useFolder() {
  const [state, setState] = useState<FolderOperationState>({
    isLoading: false,
    error: null,
  });

  // Get folder store for reactive updates
  // Note: We use getState() in callbacks to avoid stale closures
  const folderStore = useFolderStore();

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

        // Get user's public key for ECIES wrapping (stored during login for both social and external wallet)
        if (!auth.derivedKeypair) {
          throw new Error('No public key available - please log in again');
        }
        const userPublicKey = auth.derivedKeypair.publicKey;

        // Create the folder (generates keys, wraps with user public key)
        const { folder, ipnsPrivateKey, folderKey } = await folderService.createFolder({
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
            unpinCid: unpinFromIpfs,
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
   * Add a file to a folder after upload.
   *
   * @param parentId - Parent folder ID ('root' or folder UUID)
   * @param fileData - Uploaded file data from upload service
   * @returns Created file entry
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
      }
    ): Promise<FileEntry> => {
      setState({ isLoading: true, error: null });
      try {
        const folders = useFolderStore.getState().folders;
        const vault = useVaultStore.getState();

        // Get parent folder state
        const parentFolder =
          parentId === 'root' ? getRootFolderState(vault, folders) : folders[parentId];

        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        // Add file to folder
        const fileEntry = await folderService.addFileToFolder({
          parentFolderState: parentFolder,
          cid: fileData.cid,
          fileKeyEncrypted: fileData.wrappedKey,
          fileIv: fileData.iv,
          name: fileData.originalName,
          size: fileData.originalSize,
        });

        // Update local state with new child
        const updatedChildren = [...parentFolder.children, fileEntry];
        useFolderStore.getState().updateFolderChildren(parentId, updatedChildren);

        setState({ isLoading: false, error: null });
        return fileEntry;
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to add file';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  /**
   * Clear error state.
   */
  const clearError = useCallback(() => {
    setState((prev) => ({ ...prev, error: null }));
  }, []);

  return {
    // State
    ...state,

    // Operations
    createFolder: handleCreate,
    renameItem: handleRename,
    moveItem: handleMove,
    deleteItem: handleDelete,
    addFile: handleAddFile,

    // Utilities
    clearError,
    calculateFolderDepth: (folderId: string) => calculateFolderDepth(folderId, folderStore.folders),
  };
}
