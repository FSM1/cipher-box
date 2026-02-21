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
} from '../api/shares/shares';

import type { ReceivedShare, SentShare } from '../stores/share.store';
import { useShareStore } from '../stores/share.store';

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
 * Look up a CipherBox user by their secp256k1 public key.
 * Returns null if no user is found (404).
 *
 * @param publicKeyHex - Uncompressed secp256k1 public key (0x04... format)
 */
export async function lookupUser(
  publicKeyHex: string
): Promise<{ userId: string; publicKey: string } | null> {
  try {
    const result = (await sharesControllerLookupUser({ publicKey: publicKeyHex })) as unknown as {
      userId: string;
      publicKey: string;
    };
    return result;
  } catch {
    // 404 = user not found
    return null;
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
