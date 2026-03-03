import { useVaultStore } from '../stores/vault.store';
import { useFolderStore } from '../stores/folder.store';
import type { FolderNode } from '../stores/folder.store';
import { useSyncStore } from '../stores/sync.store';
import { isConflictError } from '../lib/errors';
import * as folderService from '../services/folder.service';
import { resolveIpnsRecord } from '../services/ipns.service';

/**
 * Re-sync a specific folder after a 409 conflict.
 *
 * Resolves the folder's IPNS name to get fresh CID + sequenceNumber,
 * fetches and decrypts the metadata, and updates the folder store.
 */
export async function resyncFolder(folderIpnsName: string, folderId: string): Promise<void> {
  const store = useFolderStore.getState();
  const folderNode = store.folders[folderId];
  if (!folderNode) return;

  const resolved = await resolveIpnsRecord(folderIpnsName);
  if (!resolved) return;

  const remoteMetadata = await folderService.fetchAndDecryptMetadata(
    resolved.cid,
    folderNode.folderKey
  );

  store.updateFolderChildren(folderId, remoteMetadata.children ?? []);
  store.updateFolderSequence(folderId, resolved.sequenceNumber);
}

/**
 * Execute an operation with single-retry conflict resolution.
 *
 * On 409 conflict: shows sync banner, runs resync, adds jitter delay,
 * optionally runs pre-retry validation, then retries once.
 * If the retry also returns 409, throws a user-facing error.
 */
export async function withConflictRetry<T>(
  perform: () => Promise<T>,
  resync: () => Promise<void>,
  preRetry?: () => void
): Promise<T> {
  try {
    return await perform();
  } catch (err) {
    if (!isConflictError(err)) throw err;
    useSyncStore.getState().setConflict('Folder updated by another device, re-syncing...');
    try {
      await resync();
      await new Promise((r) => setTimeout(r, 100 + Math.random() * 400));
      if (preRetry) preRetry();
      return await perform();
    } catch (retryErr) {
      if (isConflictError(retryErr)) {
        throw new Error('Conflict persists after re-sync. Please try again.');
      }
      throw retryErr;
    } finally {
      useSyncStore.getState().clearConflict();
    }
  }
}

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
