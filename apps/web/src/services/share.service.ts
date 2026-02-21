/**
 * Share Service - API integration for user-to-user sharing
 *
 * Wraps the generated Orval API client for share endpoints.
 * All sharing operations flow through these functions.
 *
 * Security: The server never sees plaintext keys. All keys are
 * ECIES-wrapped for the recipient before being sent to the API.
 */

import {
  sharesControllerCreateShare,
  sharesControllerGetReceivedShares,
  sharesControllerGetSentShares,
  sharesControllerLookupUser,
  sharesControllerGetShareKeys,
  sharesControllerAddShareKeys,
  sharesControllerRevokeShare,
  sharesControllerHideShare,
  sharesControllerGetPendingRotations,
  sharesControllerUpdateShareEncryptedKey,
  sharesControllerCompleteRotation,
} from '../api/shares/shares';

import { wrapKey, bytesToHex, hexToBytes, generateRandomBytes } from '@cipherbox/crypto';
import type { ReceivedShare, SentShare } from '../stores/share.store';
import { useShareStore } from '../stores/share.store';
import type { FolderNode } from '../stores/folder.store';

/**
 * Fetch all active, non-hidden shares received by the current user.
 * Updates the share store with the results.
 */
export async function fetchReceivedShares(): Promise<ReceivedShare[]> {
  const response = (await sharesControllerGetReceivedShares()) as unknown as Array<{
    shareId: string;
    sharerPublicKey: string;
    itemType: string;
    ipnsName: string;
    itemName: string;
    encryptedKey: string;
    createdAt: string;
  }>;

  const shares: ReceivedShare[] = response.map((s) => ({
    shareId: s.shareId,
    sharerPublicKey: s.sharerPublicKey,
    itemType: s.itemType as 'folder' | 'file',
    ipnsName: s.ipnsName,
    itemName: s.itemName,
    encryptedKey: s.encryptedKey,
    createdAt: s.createdAt,
  }));

  return shares;
}

/**
 * Fetch all active shares sent by the current user.
 * Updates the share store with the results.
 */
export async function fetchSentShares(): Promise<SentShare[]> {
  const response = (await sharesControllerGetSentShares()) as unknown as Array<{
    shareId: string;
    recipientPublicKey: string;
    itemType: string;
    ipnsName: string;
    itemName: string;
    createdAt: string;
  }>;

  const shares: SentShare[] = response.map((s) => ({
    shareId: s.shareId,
    recipientPublicKey: s.recipientPublicKey,
    itemType: s.itemType as 'folder' | 'file',
    ipnsName: s.ipnsName,
    itemName: s.itemName,
    createdAt: s.createdAt,
  }));

  return shares;
}

/**
 * Check if a CipherBox user exists with the given secp256k1 public key.
 * Returns false if no user is found (404).
 *
 * @param publicKeyHex - Uncompressed secp256k1 public key (0x04... format)
 */
export async function lookupUser(publicKeyHex: string): Promise<boolean> {
  try {
    await sharesControllerLookupUser({ publicKey: publicKeyHex });
    return true;
  } catch {
    // 404 = user not found
    return false;
  }
}

/**
 * Create a new share, sharing an encrypted folder or file with another user.
 *
 * @param params.recipientPublicKey - Recipient's secp256k1 public key
 * @param params.itemType - 'folder' or 'file'
 * @param params.ipnsName - IPNS name of the shared item
 * @param params.itemName - Display name of the shared item
 * @param params.encryptedKey - Hex-encoded ECIES ciphertext of the item key
 * @param params.childKeys - Optional re-wrapped descendant keys
 */
export async function createShare(params: {
  recipientPublicKey: string;
  itemType: 'folder' | 'file';
  ipnsName: string;
  itemName: string;
  encryptedKey: string;
  childKeys?: Array<{ keyType: 'file' | 'folder'; itemId: string; encryptedKey: string }>;
}): Promise<{ shareId: string }> {
  const response = (await sharesControllerCreateShare({
    recipientPublicKey: params.recipientPublicKey,
    itemType: params.itemType,
    ipnsName: params.ipnsName,
    itemName: params.itemName,
    encryptedKey: params.encryptedKey,
    childKeys: params.childKeys?.map((k) => ({
      keyType: k.keyType,
      itemId: k.itemId,
      encryptedKey: k.encryptedKey,
    })),
  })) as unknown as { shareId: string };

  return { shareId: response.shareId };
}

/**
 * Revoke a share (soft-delete). Only the sharer can revoke.
 * Keys are kept for lazy rotation.
 */
export async function revokeShare(shareId: string): Promise<void> {
  await sharesControllerRevokeShare(shareId);
}

/**
 * Hide a share from the recipient's view. Only the recipient can hide.
 */
export async function hideShare(shareId: string): Promise<void> {
  await sharesControllerHideShare(shareId);
}

/**
 * Get all re-wrapped child keys for a share.
 * Accessible by both sharer and recipient.
 */
export async function fetchShareKeys(
  shareId: string
): Promise<Array<{ keyType: 'file' | 'folder'; itemId: string; encryptedKey: string }>> {
  const response = (await sharesControllerGetShareKeys(shareId)) as unknown as Array<{
    keyType: string;
    itemId: string;
    encryptedKey: string;
  }>;

  return response.map((k) => ({
    keyType: k.keyType as 'file' | 'folder',
    itemId: k.itemId,
    encryptedKey: k.encryptedKey,
  }));
}

/**
 * Add re-wrapped child keys to an existing share. Only the sharer can add keys.
 */
export async function addShareKeys(
  shareId: string,
  keys: Array<{ keyType: 'file' | 'folder'; itemId: string; encryptedKey: string }>
): Promise<void> {
  await sharesControllerAddShareKeys(shareId, {
    keys: keys.map((k) => ({
      keyType: k.keyType,
      itemId: k.itemId,
      encryptedKey: k.encryptedKey,
    })),
  });
}

/**
 * Get sent shares for a specific item (by IPNS name).
 * Fetches all sent shares and filters by ipnsName.
 * Uses the store cache if available and fresh.
 */
export async function getSentSharesForItem(ipnsName: string): Promise<SentShare[]> {
  const store = useShareStore.getState();

  // Use cached sent shares if available (fetched within last 30s)
  let shares = store.sentShares;
  if (!store.lastFetchedAt || Date.now() - store.lastFetchedAt > 30_000) {
    shares = await fetchSentShares();
    useShareStore.getState().setSentShares(shares);
  }

  return shares.filter((s) => s.ipnsName === ipnsName);
}

// ---------------------------------------------------------------------------
// Post-upload / post-create share key propagation
// ---------------------------------------------------------------------------

/**
 * Ensure sent shares cache is fresh (fetched within last 30s).
 * Returns the current sent shares array.
 */
async function ensureFreshSentShares(): Promise<SentShare[]> {
  const store = useShareStore.getState();
  if (store.lastFetchedAt && Date.now() - store.lastFetchedAt < 30_000) {
    return store.sentShares;
  }
  const shares = await fetchSentShares();
  useShareStore.getState().setSentShares(shares);
  return shares;
}

/**
 * Check if a folder (by IPNS name) has any active shares.
 * Used to decide whether post-upload re-wrapping is needed.
 */
export async function hasActiveShares(folderIpnsName: string): Promise<boolean> {
  const shares = await ensureFreshSentShares();
  return shares.some((s) => s.ipnsName === folderIpnsName);
}

/**
 * Find active shares that cover a given folder, including ancestor shares.
 * A folder is "covered" if it or any of its ancestor folders is shared.
 *
 * Walks the ancestor chain and checks each folder's IPNS name against sent shares.
 *
 * @param folderIpnsName - IPNS name of the current folder
 * @param folders - Current folder tree from the folder store
 * @param currentFolderId - ID of the current folder in the tree
 * @returns Array of sent shares covering this folder (may be from ancestor)
 */
export async function findCoveringShares(
  folderIpnsName: string,
  folders: Record<string, FolderNode>,
  currentFolderId: string | null
): Promise<SentShare[]> {
  const shares = await ensureFreshSentShares();
  if (shares.length === 0) return [];

  // Collect all IPNS names from this folder up to root
  const ipnsNames = new Set<string>();
  ipnsNames.add(folderIpnsName);

  let walkId = currentFolderId;
  while (walkId) {
    const node = folders[walkId];
    if (!node) break;
    ipnsNames.add(node.ipnsName);
    walkId = node.parentId;
  }

  return shares.filter((s) => ipnsNames.has(s.ipnsName));
}

/**
 * After adding a file or subfolder to a shared folder, re-wrap the new key
 * for all existing share recipients.
 *
 * This is a fire-and-forget operation -- failures are logged but don't block
 * the primary upload/create flow.
 *
 * IMPORTANT: Callers are responsible for zeroing `newItems[*].plaintextKey`
 * after this function completes. This function does NOT zero the keys because
 * some callers (e.g., subfolder creation) keep the key alive in the store.
 * Use a `finally` block to ensure zeroing even on errors.
 *
 * @param params.folderIpnsName - IPNS name of the folder being modified
 * @param params.folders - Current folder tree from the store
 * @param params.currentFolderId - ID of the current folder in the tree
 * @param params.newItems - New items whose keys need re-wrapping
 */
export async function reWrapForRecipients(params: {
  folderIpnsName: string;
  folders: Record<string, FolderNode>;
  currentFolderId: string | null;
  newItems: Array<{
    keyType: 'file' | 'folder';
    itemId: string;
    plaintextKey: Uint8Array;
  }>;
}): Promise<void> {
  const coveringShares = await findCoveringShares(
    params.folderIpnsName,
    params.folders,
    params.currentFolderId
  );

  if (coveringShares.length === 0) return;

  // For each share recipient, re-wrap all new item keys
  for (const share of coveringShares) {
    try {
      const recipientPubKey = hexToBytes(
        share.recipientPublicKey.startsWith('0x')
          ? share.recipientPublicKey.slice(2)
          : share.recipientPublicKey
      );

      const wrappedKeys: Array<{
        keyType: 'file' | 'folder';
        itemId: string;
        encryptedKey: string;
      }> = [];

      for (const item of params.newItems) {
        const wrapped = await wrapKey(item.plaintextKey, recipientPubKey);
        wrappedKeys.push({
          keyType: item.keyType,
          itemId: item.itemId,
          encryptedKey: bytesToHex(wrapped),
        });
      }

      // Add the wrapped keys to this share via API
      await addShareKeys(share.shareId, wrappedKeys);
    } catch (err) {
      console.warn(
        `[share] Failed to re-wrap keys for recipient ${share.recipientPublicKey.slice(0, 10)}...:`,
        err
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Lazy key rotation after revocation
// ---------------------------------------------------------------------------

/** A revoked share pending key rotation. */
export type PendingRotation = {
  shareId: string;
  recipientPublicKey: string;
  itemType: 'folder' | 'file';
  ipnsName: string;
  itemName: string;
  revokedAt: string;
};

/**
 * Fetch revoked shares that are pending key rotation from the server.
 * These are shares where revokedAt is set but the share has not been hard-deleted.
 */
export async function fetchPendingRotations(): Promise<PendingRotation[]> {
  const response = (await sharesControllerGetPendingRotations()) as unknown as Array<{
    shareId: string;
    recipientPublicKey: string;
    itemType: string;
    ipnsName: string;
    itemName: string;
    revokedAt: string;
  }>;

  return response.map((r) => ({
    shareId: r.shareId,
    recipientPublicKey: r.recipientPublicKey,
    itemType: r.itemType as 'folder' | 'file',
    ipnsName: r.ipnsName,
    itemName: r.itemName,
    revokedAt: r.revokedAt,
  }));
}

/**
 * Check if a folder has pending rotations (revoked shares awaiting key rotation).
 * Called before any folder modification.
 *
 * @param folderIpnsName - IPNS name of the folder being modified
 * @returns true if there are revoked shares for this folder that need rotation
 */
export async function checkPendingRotation(folderIpnsName: string): Promise<boolean> {
  const pendingRotations = await fetchPendingRotations();
  return pendingRotations.some((r) => r.ipnsName === folderIpnsName);
}

/**
 * Update the encrypted key on a share record after lazy key rotation.
 * Re-wraps the new folder key for a remaining (non-revoked) recipient.
 */
export async function updateShareKey(shareId: string, encryptedKey: string): Promise<void> {
  await sharesControllerUpdateShareEncryptedKey(shareId, { encryptedKey });
}

/**
 * Hard-delete a revoked share after rotation is complete.
 */
export async function completeShareRotation(shareId: string): Promise<void> {
  await sharesControllerCompleteRotation(shareId);
}

/**
 * Execute lazy key rotation for a folder.
 * Called when a folder modification is about to happen and pending rotations exist.
 *
 * Protocol:
 * 1. Generate new random folderKey
 * 2. Re-wrap new folderKey for each REMAINING (non-revoked) active recipient
 * 3. Update remaining shares with the new encrypted key
 * 4. Hard-delete revoked share records (rotation complete)
 * 5. Invalidate share cache
 *
 * NOTE: The actual folder metadata re-encryption (decrypt with old key, re-encrypt
 * with new key, re-publish IPNS) is handled by the caller (folder.service.ts)
 * since it has access to the folder's IPNS private key and publishing infrastructure.
 *
 * @returns The new folderKey for the caller to use
 */
export async function executeLazyRotation(params: {
  folderIpnsName: string;
  oldFolderKey: Uint8Array;
  ownerPublicKey: Uint8Array;
}): Promise<{ newFolderKey: Uint8Array }> {
  // 1. Generate new random 32-byte folderKey
  const newFolderKey = generateRandomBytes(32);

  // 2. Fetch pending rotations and active shares for this folder
  const [pendingRotations, activeSentShares] = await Promise.all([
    fetchPendingRotations(),
    getSentSharesForItem(params.folderIpnsName),
  ]);

  const revokedForFolder = pendingRotations.filter((r) => r.ipnsName === params.folderIpnsName);
  const revokedShareIds = new Set(revokedForFolder.map((r) => r.shareId));

  // Active shares that are NOT revoked -- these recipients keep access
  const remainingShares = activeSentShares.filter((s) => !revokedShareIds.has(s.shareId));

  // 3. Re-wrap new folderKey for each remaining recipient
  for (const share of remainingShares) {
    try {
      const recipientPubKey = hexToBytes(
        share.recipientPublicKey.startsWith('0x')
          ? share.recipientPublicKey.slice(2)
          : share.recipientPublicKey
      );
      const wrapped = await wrapKey(newFolderKey, recipientPubKey);
      await updateShareKey(share.shareId, bytesToHex(wrapped));
    } catch (err) {
      console.warn(
        `[share] Failed to update share key for remaining recipient ${share.recipientPublicKey.slice(0, 10)}...:`,
        err
      );
    }
  }

  // 4. Hard-delete all revoked shares for this folder
  for (const revoked of revokedForFolder) {
    try {
      await completeShareRotation(revoked.shareId);
    } catch (err) {
      console.warn(`[share] Failed to complete rotation for share ${revoked.shareId}:`, err);
    }
  }

  // 5. Invalidate the sent shares cache so next check fetches fresh state
  useShareStore.getState().setSentShares([]);

  return { newFolderKey };
}
