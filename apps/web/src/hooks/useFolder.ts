import { useState, useCallback } from 'react';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useAuthStore } from '../stores/auth.store';
import { unpinFromIpfs } from '../lib/api/ipfs';
import { useQuotaStore } from '../stores/quota.store';
import * as folderService from '../services/folder.service';
import { reWrapForRecipients } from '../services/share.service';
import {
  createFileMetadata,
  resolveFileMetadata,
  updateFileMetadata,
  shouldCreateVersion,
  restoreVersion,
  deleteVersion,
  getFileIpnsPrivateKey,
} from '../services/file-metadata.service';
import type { FileIpnsRecordPayload } from '../services/file-metadata.service';
import type { FolderNode } from '../stores/folder.store';
import type { FolderEntry, FilePointer, FolderChild } from '@cipherbox/crypto';
import { unwrapKey, hexToBytes } from '@cipherbox/crypto';

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

        // Update local state — remove all nested folders from store
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

  /**
   * Add a file to a folder after upload (v2).
   *
   * Creates per-file IPNS metadata, then registers FilePointer in folder.
   *
   * @param parentId - Parent folder ID ('root' or folder UUID)
   * @param fileData - Uploaded file data from upload service
   * @returns Created file pointer
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
        mimeType?: string;
        encryptionMode?: 'GCM' | 'CTR';
      }
    ): Promise<FilePointer> => {
      setState({ isLoading: true, error: null });
      try {
        const folders = useFolderStore.getState().folders;
        const vault = useVaultStore.getState();
        const auth = useAuthStore.getState();

        if (!auth.vaultKeypair) {
          throw new Error('No ECIES keypair available - please log in again');
        }

        // Get parent folder state
        const parentFolder =
          parentId === 'root' ? getRootFolderState(vault, folders) : folders[parentId];

        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        // 1. Generate fileId and create per-file IPNS metadata
        const fileId = crypto.randomUUID();
        const { ipnsRecord, ipnsPrivateKeyEncrypted } = await createFileMetadata({
          fileId,
          cid: fileData.cid,
          fileKeyEncrypted: fileData.wrappedKey,
          fileIv: fileData.iv,
          size: fileData.originalSize,
          mimeType: fileData.mimeType ?? 'application/octet-stream',
          folderKey: parentFolder.folderKey,
          userPublicKey: auth.vaultKeypair.publicKey,
          encryptionMode: fileData.encryptionMode,
        });

        // 2. Register FilePointer in folder (batch publishes file + folder IPNS)
        const { filePointer, newSequenceNumber } = await folderService.addFileToFolder({
          parentFolderState: parentFolder,
          fileId,
          name: fileData.originalName,
          fileIpnsRecord: ipnsRecord,
          ipnsPrivateKeyEncrypted,
        });

        // 3. Update local state with new child and sequence number
        const updatedChildren: FolderChild[] = [...parentFolder.children, filePointer];
        const store = useFolderStore.getState();
        store.updateFolderChildren(parentId, updatedChildren);
        store.updateFolderSequence(parentId, newSequenceNumber);

        // 4. Post-upload: re-wrap file key for share recipients (fire-and-forget)
        // Unwrap the fileKey from the owner-wrapped key, then delegate to reWrapForRecipients
        (async () => {
          try {
            const authState = useAuthStore.getState();
            if (!authState.vaultKeypair) return;
            const fileKey = await unwrapKey(
              hexToBytes(fileData.wrappedKey),
              authState.vaultKeypair.privateKey
            );
            try {
              await reWrapForRecipients({
                folderIpnsName: parentFolder.ipnsName,
                folders: useFolderStore.getState().folders,
                currentFolderId: parentFolder.id,
                newItems: [{ keyType: 'file', itemId: fileId, plaintextKey: fileKey }],
              });
            } finally {
              fileKey.fill(0);
            }
          } catch (err) {
            console.warn('[share] Post-upload file re-wrapping failed:', err);
          }
        })();

        setState({ isLoading: false, error: null });
        return filePointer;
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to add file';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  /**
   * Add multiple files to a folder after upload (v2 batch).
   *
   * Creates per-file IPNS metadata for each file, then registers all
   * FilePointers via a single batch IPNS publish.
   *
   * @param parentId - Parent folder ID ('root' or folder UUID)
   * @param filesData - Array of uploaded file data from upload service
   * @returns Created file pointers
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
        mimeType?: string;
        encryptionMode?: 'GCM' | 'CTR';
      }>
    ): Promise<FilePointer[]> => {
      setState({ isLoading: true, error: null });
      try {
        const folders = useFolderStore.getState().folders;
        const vault = useVaultStore.getState();
        const auth = useAuthStore.getState();

        if (!auth.vaultKeypair) {
          throw new Error('No ECIES keypair available - please log in again');
        }

        // Get parent folder state
        const parentFolder =
          parentId === 'root' ? getRootFolderState(vault, folders) : folders[parentId];

        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        // 1. Create per-file IPNS metadata for each file
        const userPublicKey = auth.vaultKeypair.publicKey;
        const filesWithRecords = await Promise.all(
          filesData.map(async (f) => {
            const fileId = crypto.randomUUID();
            const { ipnsRecord, ipnsPrivateKeyEncrypted } = await createFileMetadata({
              fileId,
              cid: f.cid,
              fileKeyEncrypted: f.wrappedKey,
              fileIv: f.iv,
              size: f.originalSize,
              mimeType: f.mimeType ?? 'application/octet-stream',
              folderKey: parentFolder.folderKey,
              userPublicKey,
              encryptionMode: f.encryptionMode,
            });
            return {
              fileId,
              name: f.originalName,
              fileIpnsRecord: ipnsRecord,
              ipnsPrivateKeyEncrypted,
            };
          })
        );

        // 2. Register FilePointers in folder (batch publishes all IPNS records)
        const { filePointers, newSequenceNumber } = await folderService.addFilesToFolder({
          parentFolderState: parentFolder,
          files: filesWithRecords,
        });

        // 3. Update local state with new children and sequence number
        const store = useFolderStore.getState();
        store.updateFolderChildren(parentId, [...parentFolder.children, ...filePointers]);
        store.updateFolderSequence(parentId, newSequenceNumber);

        // 4. Post-upload: re-wrap file keys for share recipients (fire-and-forget)
        (async () => {
          try {
            const authState = useAuthStore.getState();
            if (!authState.vaultKeypair) return;
            const privateKey = authState.vaultKeypair.privateKey;
            const newItems: Array<{
              keyType: 'file' | 'folder';
              itemId: string;
              plaintextKey: Uint8Array;
            }> = [];
            for (let i = 0; i < filesData.length; i++) {
              const fileKey = await unwrapKey(hexToBytes(filesData[i].wrappedKey), privateKey);
              newItems.push({
                keyType: 'file',
                itemId: filesWithRecords[i].fileId,
                plaintextKey: fileKey,
              });
            }
            try {
              await reWrapForRecipients({
                folderIpnsName: parentFolder.ipnsName,
                folders: useFolderStore.getState().folders,
                currentFolderId: parentFolder.id,
                newItems,
              });
            } finally {
              for (const item of newItems) {
                item.plaintextKey.fill(0);
              }
            }
          } catch (err) {
            console.warn('[share] Post-upload batch file re-wrapping failed:', err);
          }
        })();

        setState({ isLoading: false, error: null });
        return filePointers;
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to add files';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  /**
   * Update a file's content in-place (v2: re-encrypt, update file IPNS, folder untouched).
   *
   * Old CIDs are preserved as version history (VER-01). Only pruned versions
   * (excess beyond max 10) have their CIDs unpinned.
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
        forceVersion?: boolean; // true for web re-upload, false/undefined for text editor
      }
    ): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const folders = useFolderStore.getState().folders;
        const vault = useVaultStore.getState();
        const auth = useAuthStore.getState();

        if (!auth.vaultKeypair) {
          throw new Error('No ECIES keypair available - please log in again');
        }

        // Get parent folder state
        const parentFolder =
          parentId === 'root' ? getRootFolderState(vault, folders) : folders[parentId];

        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        // 1. Find the FilePointer in parent's children
        const filePointer = parentFolder.children.find(
          (c) => c.type === 'file' && c.id === fileData.fileId
        ) as FilePointer | undefined;

        if (!filePointer) {
          throw new Error('File not found in folder');
        }

        // 2. Resolve current file metadata from IPNS
        const { metadata: currentMetadata } = await resolveFileMetadata(
          filePointer.fileMetaIpnsName,
          parentFolder.folderKey
        );

        // 3. Decrypt the file IPNS private key from FilePointer (or HKDF fallback)
        const { privateKey: fileIpnsPrivateKey, migratedIpnsPrivateKeyEncrypted } =
          await getFileIpnsPrivateKey(
            filePointer,
            auth.vaultKeypair.privateKey,
            auth.vaultKeypair.publicKey
          );

        // 4. Determine whether to create a version entry
        const createVersion = shouldCreateVersion(currentMetadata, fileData.forceVersion ?? false);

        let ipnsRecord: FileIpnsRecordPayload;
        let prunedCids: string[];
        try {
          // 5. Update file metadata and publish new IPNS record
          ({ ipnsRecord, prunedCids } = await updateFileMetadata({
            fileIpnsPrivateKey,
            fileMetaIpnsName: filePointer.fileMetaIpnsName,
            folderKey: parentFolder.folderKey,
            currentMetadata,
            updates: {
              cid: fileData.newCid,
              fileKeyEncrypted: fileData.newFileKeyEncrypted,
              fileIv: fileData.newFileIv,
              size: fileData.newSize,
            },
            createVersion,
          }));
        } finally {
          fileIpnsPrivateKey.fill(0);
        }

        // 6. Publish only the file IPNS record (folder metadata untouched!)
        await folderService.replaceFileInFolder({
          fileId: fileData.fileId,
          fileIpnsRecord: ipnsRecord,
          parentFolderState: parentFolder,
        });

        // 7. Update local state -- touch modifiedAt and persist migrated IPNS key if applicable
        const updatedChildren = parentFolder.children.map((child) => {
          if (child.type === 'file' && child.id === fileData.fileId) {
            return {
              ...child,
              modifiedAt: Date.now(),
              ...(migratedIpnsPrivateKeyEncrypted
                ? { ipnsPrivateKeyEncrypted: migratedIpnsPrivateKeyEncrypted }
                : {}),
            };
          }
          return child;
        });

        const store = useFolderStore.getState();
        store.updateFolderChildren(parentId, updatedChildren);

        // 7b. Lazy migration: persist wrapped IPNS key to folder metadata on IPFS
        if (migratedIpnsPrivateKeyEncrypted) {
          folderService
            .updateFolderMetadata({
              folderId: parentFolder.id,
              children: updatedChildren,
              folderKey: parentFolder.folderKey,
              ipnsPrivateKey: parentFolder.ipnsPrivateKey,
              ipnsName: parentFolder.ipnsName,
              sequenceNumber: parentFolder.sequenceNumber,
            })
            .then(({ newSequenceNumber }) => {
              useFolderStore.getState().updateFolderSequence(parentId, newSequenceNumber);
            })
            .catch((err) => {
              console.warn('Lazy IPNS key migration: folder re-publish failed, will retry:', err);
            });
        }

        // 8. Only unpin CIDs of pruned versions (excess beyond max 10)
        // Old CIDs stay pinned as version history (VER-01)
        for (const prunedCid of prunedCids) {
          unpinFromIpfs(prunedCid).catch(() => {});
        }

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
   * Restore a previous version of a file.
   *
   * Swaps the current content with a past version. The current content becomes
   * a new version entry (non-destructive). Publishes updated IPNS record and
   * unpins any pruned version CIDs.
   *
   * @param parentId - Parent folder ID ('root' or folder UUID)
   * @param fileId - File ID (UUID)
   * @param versionIndex - Index of version to restore (0 = newest past version)
   */
  const handleRestoreVersion = useCallback(
    async (parentId: string, fileId: string, versionIndex: number): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const folders = useFolderStore.getState().folders;
        const vault = useVaultStore.getState();
        const auth = useAuthStore.getState();

        if (!auth.vaultKeypair) {
          throw new Error('No ECIES keypair available - please log in again');
        }

        // Get parent folder state
        const parentFolder =
          parentId === 'root' ? getRootFolderState(vault, folders) : folders[parentId];

        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        // Find the FilePointer
        const filePointer = parentFolder.children.find(
          (c) => c.type === 'file' && c.id === fileId
        ) as FilePointer | undefined;

        if (!filePointer) {
          throw new Error('File not found in folder');
        }

        // Resolve current file metadata from IPNS
        const { metadata: currentMetadata } = await resolveFileMetadata(
          filePointer.fileMetaIpnsName,
          parentFolder.folderKey
        );

        // Decrypt the file IPNS private key from FilePointer (or HKDF fallback)
        const { privateKey: fileIpnsPrivateKey, migratedIpnsPrivateKeyEncrypted } =
          await getFileIpnsPrivateKey(
            filePointer,
            auth.vaultKeypair.privateKey,
            auth.vaultKeypair.publicKey
          );

        let ipnsRecord: FileIpnsRecordPayload;
        let prunedCids: string[];
        try {
          // Call restoreVersion service function
          ({ ipnsRecord, prunedCids } = await restoreVersion({
            fileIpnsPrivateKey,
            fileMetaIpnsName: filePointer.fileMetaIpnsName,
            folderKey: parentFolder.folderKey,
            currentMetadata,
            versionIndex,
          }));
        } finally {
          fileIpnsPrivateKey.fill(0);
        }

        // Publish the IPNS record (folder metadata untouched)
        await folderService.replaceFileInFolder({
          fileId,
          fileIpnsRecord: ipnsRecord,
          parentFolderState: parentFolder,
        });

        // Update local folder state (modifiedAt and migrated IPNS key on FilePointer)
        const updatedChildren = parentFolder.children.map((child) => {
          if (child.type === 'file' && child.id === fileId) {
            return {
              ...child,
              modifiedAt: Date.now(),
              ...(migratedIpnsPrivateKeyEncrypted
                ? { ipnsPrivateKeyEncrypted: migratedIpnsPrivateKeyEncrypted }
                : {}),
            };
          }
          return child;
        });
        useFolderStore.getState().updateFolderChildren(parentId, updatedChildren);

        // Lazy migration: persist wrapped IPNS key to folder metadata on IPFS
        if (migratedIpnsPrivateKeyEncrypted) {
          folderService
            .updateFolderMetadata({
              folderId: parentFolder.id,
              children: updatedChildren,
              folderKey: parentFolder.folderKey,
              ipnsPrivateKey: parentFolder.ipnsPrivateKey,
              ipnsName: parentFolder.ipnsName,
              sequenceNumber: parentFolder.sequenceNumber,
            })
            .then(({ newSequenceNumber }) => {
              useFolderStore.getState().updateFolderSequence(parentId, newSequenceNumber);
            })
            .catch((err) => {
              console.warn('Lazy IPNS key migration: folder re-publish failed, will retry:', err);
            });
        }

        // Unpin pruned version CIDs
        for (const prunedCid of prunedCids) {
          unpinFromIpfs(prunedCid).catch(() => {});
        }

        // Refresh quota
        useQuotaStore.getState().fetchQuota();

        setState({ isLoading: false, error: null });
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to restore version';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  /**
   * Delete a specific past version from a file's version history.
   *
   * Removes the version from metadata, publishes updated IPNS record, and
   * unpins the deleted version's CID.
   *
   * @param parentId - Parent folder ID ('root' or folder UUID)
   * @param fileId - File ID (UUID)
   * @param versionIndex - Index of version to delete (0 = newest past version)
   */
  const handleDeleteVersion = useCallback(
    async (parentId: string, fileId: string, versionIndex: number): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const folders = useFolderStore.getState().folders;
        const vault = useVaultStore.getState();
        const auth = useAuthStore.getState();

        if (!auth.vaultKeypair) {
          throw new Error('No ECIES keypair available - please log in again');
        }

        // Get parent folder state
        const parentFolder =
          parentId === 'root' ? getRootFolderState(vault, folders) : folders[parentId];

        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        // Find the FilePointer
        const filePointer = parentFolder.children.find(
          (c) => c.type === 'file' && c.id === fileId
        ) as FilePointer | undefined;

        if (!filePointer) {
          throw new Error('File not found in folder');
        }

        // Resolve current file metadata from IPNS
        const { metadata: currentMetadata } = await resolveFileMetadata(
          filePointer.fileMetaIpnsName,
          parentFolder.folderKey
        );

        // Decrypt the file IPNS private key from FilePointer (or HKDF fallback)
        const { privateKey: fileIpnsPrivateKey, migratedIpnsPrivateKeyEncrypted } =
          await getFileIpnsPrivateKey(
            filePointer,
            auth.vaultKeypair.privateKey,
            auth.vaultKeypair.publicKey
          );

        let ipnsRecord: FileIpnsRecordPayload;
        let deletedCid: string;
        try {
          // Call deleteVersion service function
          ({ ipnsRecord, deletedCid } = await deleteVersion({
            fileIpnsPrivateKey,
            fileMetaIpnsName: filePointer.fileMetaIpnsName,
            folderKey: parentFolder.folderKey,
            currentMetadata,
            versionIndex,
          }));
        } finally {
          fileIpnsPrivateKey.fill(0);
        }

        // Publish the IPNS record (folder metadata untouched)
        await folderService.replaceFileInFolder({
          fileId,
          fileIpnsRecord: ipnsRecord,
          parentFolderState: parentFolder,
        });

        // Lazy migration: persist wrapped IPNS key to folder metadata on IPFS
        if (migratedIpnsPrivateKeyEncrypted) {
          const updatedChildren = parentFolder.children.map((child) => {
            if (child.type === 'file' && child.id === fileId) {
              return { ...child, ipnsPrivateKeyEncrypted: migratedIpnsPrivateKeyEncrypted };
            }
            return child;
          });
          useFolderStore.getState().updateFolderChildren(parentId, updatedChildren);

          folderService
            .updateFolderMetadata({
              folderId: parentFolder.id,
              children: updatedChildren,
              folderKey: parentFolder.folderKey,
              ipnsPrivateKey: parentFolder.ipnsPrivateKey,
              ipnsName: parentFolder.ipnsName,
              sequenceNumber: parentFolder.sequenceNumber,
            })
            .then(({ newSequenceNumber }) => {
              useFolderStore.getState().updateFolderSequence(parentId, newSequenceNumber);
            })
            .catch((err) => {
              console.warn('Lazy IPNS key migration: folder re-publish failed, will retry:', err);
            });
        }

        // Unpin deleted version CID
        unpinFromIpfs(deletedCid).catch(() => {});

        // Refresh quota
        useQuotaStore.getState().fetchQuota();

        setState({ isLoading: false, error: null });
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to delete version';
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
    restoreVersion: handleRestoreVersion,
    deleteVersion: handleDeleteVersion,

    // Utilities
    clearError,
    calculateFolderDepth: (folderId: string) => calculateFolderDepth(folderId, folderStore.folders),
  };
}
