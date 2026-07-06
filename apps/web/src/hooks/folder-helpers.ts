import { useVaultStore } from '../stores/vault.store';
import { useFolderStore } from '../stores/folder.store';
import type { FolderNode } from '../stores/folder.store';
import { getDepth } from '@cipherbox/sdk';
import { getSdkClient } from '../lib/sdk-provider';

/**
 * Re-sync a specific folder after a 409 conflict.
 *
 * Routes through the SDK's gated read path (`client.listFolder` /
 * `client.getFolderMetadata`, both backed by `ensureFolderLoaded` -- ROT-07
 * durable anti-rollback floor) instead of the web's own un-gated
 * `resolveIpnsRecord` + `fetchAndDecryptMetadata` call (SC#1, T-68.2-04).
 *
 * `listFolder` is called first so this resync also warms the SDK's
 * `ResolvedChild[]` listing cache (kind/size/modifiedAt pre-resolved,
 * SC#2) for any Plan-09 store projection consuming it; `getFolderMetadata`
 * (a cache-hit on the same just-loaded `FolderState`, zero extra network
 * cost) supplies the raw `SealedChildRef[]` the store's `children` field
 * still needs for write-path/crypto identity (D-09).
 */
export async function resyncFolder(folderIpnsName: string, folderId: string): Promise<void> {
  const store = useFolderStore.getState();
  const folderNode = store.folders[folderId];
  if (!folderNode) return;

  const client = getSdkClient();
  await client.listFolder(folderIpnsName);
  const metadata = await client.getFolderMetadata(folderIpnsName);
  if (!metadata) return;

  const resyncChildren = metadata.children ?? [];
  store.updateFolderChildren(folderId, resyncChildren);
  // `Node` carries no sequenceNumber of its own (that's an IPNS envelope-level
  // field, not part of the decrypted content) -- the store's sequenceNumber
  // is left untouched here; Plan 09's freshness wiring is the designated
  // place to thread a resolved envelope sequence back through the facade.
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
