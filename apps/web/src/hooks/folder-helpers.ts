import { useVaultStore } from '../stores/vault.store';
import type { FolderNode } from '../stores/folder.store';
import * as folderService from '../services/folder.service';

/** Maximum folder nesting depth per FOLD-03 */
export const MAX_FOLDER_DEPTH = 20;

/**
 * State for folder operations.
 */
export type FolderOperationState = {
  isLoading: boolean;
  error: string | null;
};

/**
 * Get the root folder state from vault and folder stores.
 * Root folder uses vault keys directly.
 */
export function getRootFolderState(
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
export function calculateFolderDepth(
  folderId: string,
  folders: Record<string, FolderNode>
): number {
  return folderService.getDepth(folderId, folders);
}
