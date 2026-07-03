import { useVaultStore } from '../stores/vault.store';
import { useFolderStore } from '../stores/folder.store';
import type { FolderNode } from '../stores/folder.store';
import { fetchAndDecryptMetadata, getDepth } from '@cipherbox/sdk-core';
import { getSdkClient } from '../lib/sdk-provider';
import { resolveIpnsRecord } from '../services/ipns.service';
import { resolveKinds } from '../lib/kind-cache';

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

  const remoteMetadata = await fetchAndDecryptMetadata(
    resolved.cid,
    folderNode.folderKey,
    getSdkClient().getContext()
  );

  // T-68.1-33-01: direct owner-side inserter (409-conflict resync) — warm the
  // kind cache BEFORE projecting so a row is never interactable while its
  // kind is unresolved, mirroring navigateTo's D-02 ordering.
  const resyncChildren = remoteMetadata.children ?? [];
  await resolveKinds(resyncChildren);
  store.updateFolderChildren(folderId, resyncChildren);
  store.updateFolderSequence(folderId, resolved.sequenceNumber);
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
