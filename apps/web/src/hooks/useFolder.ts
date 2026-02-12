import { useState, useCallback } from 'react';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useAuthStore } from '../stores/auth.store';
import { unpinFromIpfs } from '../lib/api/ipfs';
import { useQuotaStore } from '../stores/quota.store';
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

        // Get user's ECIES keypair for vault cryptographic operations (public + private keys stored in memory after login)
        // The public key is used here for key wrapping; the private key remains client-side for decryption operations.
        if (!auth.derivedKeypair) {
          throw new Error('No ECIES keypair available - please log in again');
        }
        const userPublicKey = auth.derivedKeypair.publicKey;

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
        for (const child of movedChildren) {
          // Name collision check
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

        await folderService.updateFolderMetadata({
          folderId: destFolder.id,
          children: destChildren,
          folderKey: destFolder.folderKey,
          ipnsPrivateKey: destFolder.ipnsPrivateKey,
          ipnsName: destFolder.ipnsName,
          sequenceNumber: destFolder.sequenceNumber,
        });

        // REMOVE all from source AFTER destination confirmed
        const sourceChildren = sourceFolder.children.filter((c) => !itemIds.has(c.id));

        await folderService.updateFolderMetadata({
          folderId: sourceFolder.id,
          children: sourceChildren,
          folderKey: sourceFolder.folderKey,
          ipnsPrivateKey: sourceFolder.ipnsPrivateKey,
          ipnsName: sourceFolder.ipnsName,
          sequenceNumber: sourceFolder.sequenceNumber,
        });

        // Update local state
        const store = useFolderStore.getState();
        store.updateFolderChildren(sourceParentId, sourceChildren);
        store.updateFolderChildren(destParentId, destChildren);

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
        const cidsToUnpin: string[] = [];

        // Collect CIDs to unpin from files and recursive folder contents
        for (const item of items) {
          if (item.type === 'file') {
            const file = parentFolder.children.find((c) => c.id === item.id && c.type === 'file');
            if (file && 'cid' in file) {
              cidsToUnpin.push(file.cid);
            }
          } else {
            // Recursively collect CIDs from folder subtree
            const collectCids = (folderId: string) => {
              const folder = folders[folderId];
              if (!folder) return;
              for (const child of folder.children) {
                if (child.type === 'file' && 'cid' in child) {
                  cidsToUnpin.push(child.cid);
                } else if (child.type === 'folder') {
                  collectCids(child.id);
                }
              }
            };
            collectCids(item.id);
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

        // Update local state
        const store = useFolderStore.getState();
        store.updateFolderChildren(parentId, updatedChildren);
        for (const item of items) {
          if (item.type === 'folder') {
            store.removeFolder(item.id);
          }
        }

        // Fire-and-forget unpin all CIDs
        Promise.all(cidsToUnpin.map((cid) => unpinFromIpfs(cid).catch(() => {})));

        setState({ isLoading: false, error: null });
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to delete items';
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
        const { fileEntry, newSequenceNumber } = await folderService.addFileToFolder({
          parentFolderState: parentFolder,
          cid: fileData.cid,
          fileKeyEncrypted: fileData.wrappedKey,
          fileIv: fileData.iv,
          name: fileData.originalName,
          size: fileData.originalSize,
        });

        // Update local state with new child and sequence number
        const updatedChildren = [...parentFolder.children, fileEntry];
        const store = useFolderStore.getState();
        store.updateFolderChildren(parentId, updatedChildren);
        store.updateFolderSequence(parentId, newSequenceNumber);

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
   * Add multiple files to a folder after upload (batch).
   *
   * Registers all files in a single folder metadata update with one IPNS publish.
   *
   * @param parentId - Parent folder ID ('root' or folder UUID)
   * @param filesData - Array of uploaded file data from upload service
   * @returns Created file entries
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
      }>
    ): Promise<FileEntry[]> => {
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

        // Batch add files to folder (single IPNS publish)
        const { fileEntries, newSequenceNumber } = await folderService.addFilesToFolder({
          parentFolderState: parentFolder,
          files: filesData.map((f) => ({
            cid: f.cid,
            fileKeyEncrypted: f.wrappedKey,
            fileIv: f.iv,
            name: f.originalName,
            size: f.originalSize,
          })),
        });

        // Update local state with new children and sequence number
        const store = useFolderStore.getState();
        store.updateFolderChildren(parentId, [...parentFolder.children, ...fileEntries]);
        store.updateFolderSequence(parentId, newSequenceNumber);

        setState({ isLoading: false, error: null });
        return fileEntries;
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to add files';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  /**
   * Update a file's content in-place (re-encrypt and replace CID).
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
      }
    ): Promise<void> => {
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

        // Replace file in folder metadata
        const { newSequenceNumber, oldCid } = await folderService.replaceFileInFolder({
          fileId: fileData.fileId,
          newCid: fileData.newCid,
          newFileKeyEncrypted: fileData.newFileKeyEncrypted,
          newFileIv: fileData.newFileIv,
          newSize: fileData.newSize,
          parentFolderState: parentFolder,
        });

        // Update local state with modified children
        const updatedChildren = parentFolder.children.map((child) => {
          if (child.type === 'file' && child.id === fileData.fileId) {
            return {
              ...child,
              cid: fileData.newCid,
              fileKeyEncrypted: fileData.newFileKeyEncrypted,
              fileIv: fileData.newFileIv,
              size: fileData.newSize,
              modifiedAt: Date.now(),
            };
          }
          return child;
        });

        const store = useFolderStore.getState();
        store.updateFolderChildren(parentId, updatedChildren);
        store.updateFolderSequence(parentId, newSequenceNumber);

        // Unpin old CID fire-and-forget
        unpinFromIpfs(oldCid).catch(() => {});

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
    moveItems: handleMoveItems,
    deleteItem: handleDelete,
    deleteItems: handleDeleteItems,
    addFile: handleAddFile,
    addFiles: handleAddFiles,
    updateFile: handleUpdateFile,

    // Utilities
    clearError,
    calculateFolderDepth: (folderId: string) => calculateFolderDepth(folderId, folderStore.folders),
  };
}
