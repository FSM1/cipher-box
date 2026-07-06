import { useVaultStore } from '../stores/vault.store';
import { useFolderStore } from '../stores/folder.store';
import type { FolderNode } from '../stores/folder.store';
import { getDepth } from '@cipherbox/sdk';
import { getSdkClient } from '../lib/sdk-provider';

/**
 * Re-sync a specific folder after a 409 conflict.
 *
 * Routes through the SDK's gated read path (`client.listFolder` /
 * `client.ensureFolderLoaded`, both backed by ROT-07's durable anti-rollback
 * floor) instead of the web's own un-gated `resolveIpnsRecord` +
 * `fetchAndDecryptMetadata` call (SC#1, T-68.2-04).
 *
 * `listFolder` resolves the SDK's `ResolvedChild[]` display projection
 * (kind/size/modifiedAt pre-resolved, SC#2) -- this IS the store's
 * `children` field (Plan 09, SC#3: the store never independently
 * resolves). `ensureFolderLoaded` (a cache-hit on the same just-loaded
 * `FolderState`, zero extra network cost) supplies the raw
 * `SealedChildRef[]` (`rawChildren`) and current `sequenceNumber` the
 * write path still needs (D-09).
 */
export async function resyncFolder(folderIpnsName: string, folderId: string): Promise<void> {
  const store = useFolderStore.getState();
  const folderNode = store.folders[folderId];
  if (!folderNode) return;

  // 68.2-16: force a live resolve on both legs -- this runs after a local
  // write lost a 409 CAS race, so the SDK cache may still hold the pre-write
  // listing for this ipnsName+sequence; forcing guarantees the re-sync reflects
  // the winning record (D-03 deterministic freshness leg).
  const client = getSdkClient();
  const resolved = await client.listFolder(folderIpnsName, { forceResolve: true });
  const state = await client.ensureFolderLoaded(folderIpnsName, { forceResolve: true });

  // Re-read the store after the awaits: the folder may have been navigated
  // away from or removed while resolving (matches refreshFolderListing /
  // invalidateOpenFolder). Skip the writeback if it's gone.
  const freshStore = useFolderStore.getState();
  if (!freshStore.folders[folderId]) return;
  freshStore.updateFolderChildren(folderId, resolved);
  if (state) {
    freshStore.updateFolderRawChildren(folderId, state.children);
    freshStore.updateFolderSequence(folderId, state.sequenceNumber);
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
  if (!vaultStore.rootReadKey || !vaultStore.rootIpnsKeypair || !vaultStore.rootIpnsName) {
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
    folderKey: vaultStore.rootReadKey,
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
  return getDepth(folderId, folders);
}
