// DEPRECATED: Use @cipherbox/sdk instead. Will be removed in 19.1-06.
// Hooks now delegate to CipherBoxClient SDK methods for share operations.
// Remaining usages: reWrapForRecipients (useFolderMutations, useFileOperations).
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
  sharesControllerLookupUser,
  sharesControllerRevokeShare,
  sharesControllerHideShare,
  sharesControllerUpdateShareItemName,
  type ShareKeyEntryDtoKeyType,
  type ChildKeyDtoKeyType,
} from '@cipherbox/api-client';

import { wrapKey, unwrapKey, bytesToHex, hexToBytes, generateRandomBytes } from '@cipherbox/crypto';
import type { ReceivedShare, SentShare } from '../stores/share.store';
import { useShareStore } from '../stores/share.store';
import type { FolderNode } from '../stores/folder.store';
import { useAuthStore } from '../stores/auth.store';
import { logger } from '../lib/logger';

// ---------------------------------------------------------------------------
// REQ-4 — share itemName ECIES at-rest (Phase-14 M1 closure)
//
// itemName is wrapped with the RECIPIENT's secp256k1 public key (the same key
// already used for encryptedKey) before leaving the browser. Recipients decrypt
// itemNameEncrypted with their vault private key for display; the owner's
// sent-share list keeps the plaintext projection it had at create time and
// falls back to any legacy plaintext itemName when ciphertext is present but
// not decryptable (the name was wrapped for the recipient, not the owner).
//
// Security: never log itemName or itemNameEncrypted; zero transient unwrapped
// bytes after use (CLAUDE.md rule 9).
// ---------------------------------------------------------------------------

/** Minimal projection of a share/invite row carrying the itemName fields. */
export type ItemNameBearingRow = {
  itemName: string;
  itemNameEncrypted?: string | null;
};

/**
 * Decrypt a share/invite display name for rendering.
 *
 * When `itemNameEncrypted` (hex ECIES ciphertext) is present, unwrap it with the
 * vault private key and return the UTF-8 name. When absent (legacy plaintext
 * row), fall back to the plaintext `itemName`.
 *
 * @param row - Row carrying itemName + optional itemNameEncrypted (hex)
 * @param vaultPrivateKey - The viewer's secp256k1 vault private key
 */
export async function decryptItemName(
  row: ItemNameBearingRow,
  vaultPrivateKey: Uint8Array
): Promise<string> {
  if (!row.itemNameEncrypted) {
    return row.itemName;
  }

  const unwrapped = await unwrapKey(hexToBytes(row.itemNameEncrypted), vaultPrivateKey);
  try {
    return new TextDecoder().decode(unwrapped);
  } finally {
    unwrapped.fill(0);
  }
}

/**
 * Lazy-backfill decision predicate (decision A2).
 *
 * Returns true only when a key-holding client (one that holds the recipient
 * pubkey to re-wrap with) sees a legacy plaintext-only row: plaintext present,
 * ciphertext absent. Idempotent — returns false once ciphertext exists, so a
 * backfilled row is never re-backfilled.
 *
 * @param row - Row carrying itemName + optional itemNameEncrypted
 * @param hasRecipientPubKey - Whether the caller holds the recipient pubkey
 */
export function shouldBackfill(row: ItemNameBearingRow, hasRecipientPubKey: boolean): boolean {
  if (!hasRecipientPubKey) return false;
  if (row.itemNameEncrypted) return false;
  return Boolean(row.itemName);
}

/**
 * Fetch active, non-hidden shares received by the current user (paginated).
 */
export async function fetchReceivedShares(
  _limit = 50,
  _offset = 0
): Promise<{ shares: ReceivedShare[]; total: number }> {
  throw new Error('deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired');
}

/**
 * Fetch active shares sent by the current user (paginated).
 */
export async function fetchSentShares(
  _limit = 50,
  _offset = 0
): Promise<{ shares: SentShare[]; total: number }> {
  throw new Error('deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired');
}

/**
 * Lazy backfill of itemNameEncrypted for legacy plaintext sent shares (decision A2).
 *
 * The owner holds the recipient pubkey on each sent-share row, so it can re-wrap
 * the plaintext display name for the recipient and re-persist the ciphertext.
 * Best-effort and idempotent: rows already carrying ciphertext are skipped via
 * shouldBackfill, so a backfilled row is never re-wrapped. Failures are logged
 * (never throwing) so the share-list load is never blocked.
 *
 * Persists via `PATCH /shares/:id/item-name`, which only the sharer may call
 * and which stores the client-supplied ciphertext as-is (server never encrypts).
 *
 * @returns Count of rows successfully backfilled (re-wrapped and persisted).
 */
export async function backfillSentShareItemNames(shares: SentShare[]): Promise<number> {
  const vaultKeypair = useAuthStore.getState().vaultKeypair;
  if (!vaultKeypair) return 0;

  let backfilled = 0;

  for (const share of shares) {
    // Owner always holds the recipient pubkey on the row → key-holder = true.
    if (!shouldBackfill(share, true)) continue;

    try {
      const recipientPubKey = hexToBytes(
        share.recipientPublicKey.startsWith('0x')
          ? share.recipientPublicKey.slice(2)
          : share.recipientPublicKey
      );
      const plaintextNameBytes = new TextEncoder().encode(share.itemName);
      let wrapped: Uint8Array | null = null;
      try {
        wrapped = await wrapKey(plaintextNameBytes, recipientPubKey);
        const itemNameEncrypted = bytesToHex(wrapped);

        // Persist the re-wrapped ciphertext for this legacy row. Only the sharer
        // may update it; the server stores the ciphertext as-is.
        await sharesControllerUpdateShareItemName(share.shareId, { itemNameEncrypted });
        backfilled += 1;
      } finally {
        // Clear the transient plaintext display name from memory after wrapping.
        plaintextNameBytes.fill(0);
        wrapped?.fill(0);
      }
    } catch (err) {
      // Never log the plaintext/ciphertext name; only the failure marker.
      logger.warn('[share] itemName backfill re-wrap failed for share', share.shareId, err);
    }
  }

  return backfilled;
}

/**
 * Check if a CipherBox user exists with the given secp256k1 public key.
 *
 * @param publicKeyHex - Uncompressed secp256k1 public key (0x04... format)
 */
export async function lookupUser(publicKeyHex: string): Promise<boolean> {
  const result = await sharesControllerLookupUser({ publicKey: publicKeyHex });
  return result.exists;
}

/**
 * Create a new share, sharing an encrypted folder or file with another user.
 *
 * @param params.recipientPublicKey - Recipient's secp256k1 public key
 * @param params.itemType - 'folder' or 'file'
 * @param params.ipnsName - IPNS name of the shared item
 * @param params.itemName - Display name of the shared item (legacy plaintext)
 * @param params.itemNameEncrypted - Hex ECIES ciphertext of the display name
 *   wrapped for the recipient. When supplied, no plaintext name is sent.
 * @param params.encryptedKey - Hex-encoded ECIES ciphertext of the item key
 * @param params.childKeys - Optional re-wrapped descendant keys
 */
export async function createShare(_params: {
  recipientPublicKey: string;
  itemType: 'folder' | 'file';
  ipnsName: string;
  itemName: string;
  itemNameEncrypted?: string;
  encryptedKey: string;
  childKeys?: Array<{ keyType: ChildKeyDtoKeyType; itemId: string; encryptedKey: string }>;
}): Promise<{ shareId: string }> {
  throw new Error('deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired');
}

/**
 * Update the permission level of an existing share.
 * Only the sharer can change permission. Upgrading to write requires
 * an ECIES-wrapped IPNS private key for the recipient.
 *
 * @param shareId - ID of the share to update
 * @param permission - New permission level ('read' or 'write')
 * @param encryptedIpnsKey - ECIES-wrapped IPNS key (required for upgrade to write)
 */
export async function updateSharePermission(
  _shareId: string,
  _permission: 'read' | 'write',
  _encryptedIpnsKey?: string
): Promise<void> {
  throw new Error('deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired');
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
export async function fetchShareKeys(_shareId: string): Promise<
  Array<{
    keyType: ShareKeyEntryDtoKeyType;
    itemId: string;
    encryptedKey: string;
  }>
> {
  throw new Error('deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired');
}

/**
 * Add re-wrapped child keys to an existing share.
 * Allowed for the sharer (owner) or write-share recipients (file/file-ipns keys only).
 */
export async function addShareKeys(
  _shareId: string,
  _keys: Array<{
    keyType: ShareKeyEntryDtoKeyType;
    itemId: string;
    encryptedKey: string;
  }>
): Promise<void> {
  throw new Error('deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired');
}

/**
 * Get sent shares for a specific item (by IPNS name).
 * Fetches all sent shares and filters by ipnsName.
 * Uses the store cache if available and fresh.
 */
export async function getSentSharesForItem(ipnsName: string): Promise<SentShare[]> {
  const shares = await ensureFreshSentShares();
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
  if (store.lastSentFetchedAt && Date.now() - store.lastSentFetchedAt < 30_000) {
    return store.sentShares;
  }
  // Re-wrapping needs the full set — paginate through all pages
  const allShares = await fetchAllSentShares();
  useShareStore.getState().setSentShares(allShares);
  return allShares;
}

/**
 * Fetch ALL sent shares by paginating through the API.
 * The API enforces a max limit of 100 per page.
 */
async function fetchAllSentShares(): Promise<SentShare[]> {
  const pageSize = 100;
  let offset = 0;
  const allShares: SentShare[] = [];

  while (true) {
    const { shares, total } = await fetchSentShares(pageSize, offset);
    allShares.push(...shares);
    offset += shares.length;
    if (offset >= total || shares.length === 0) break;
  }

  // Lazy backfill (decision A2): re-wrap and persist itemNameEncrypted for any
  // legacy plaintext rows. Best-effort and idempotent (shouldBackfill skips rows
  // already carrying ciphertext), fire-and-forget so the list load never blocks.
  void backfillSentShareItemNames(allShares).catch((err) =>
    logger.warn('[share] itemName backfill pass failed', err)
  );

  return allShares;
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
}): Promise<{ failedRecipients: string[] }> {
  const coveringShares = await findCoveringShares(
    params.folderIpnsName,
    params.folders,
    params.currentFolderId
  );

  if (coveringShares.length === 0) return { failedRecipients: [] };

  const failedRecipients: string[] = [];

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
      logger.warn(
        `[share] Failed to re-wrap keys for recipient ${share.recipientPublicKey.slice(0, 10)}...:`,
        err
      );
      failedRecipients.push(share.recipientPublicKey);
    }
  }

  return { failedRecipients };
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
  throw new Error('deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired');
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
export async function updateShareKey(_shareId: string, _encryptedKey: string): Promise<void> {
  throw new Error('deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired');
}

/**
 * Hard-delete a revoked share after rotation is complete.
 */
export async function completeShareRotation(_shareId: string): Promise<void> {
  throw new Error('deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired');
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
  const reWrapFailures: string[] = [];
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
      logger.warn(
        `[share] Failed to update share key for remaining recipient ${share.recipientPublicKey.slice(0, 10)}...:`,
        err
      );
      reWrapFailures.push(share.shareId);
    }
  }

  if (reWrapFailures.length > 0) {
    newFolderKey.fill(0);
    throw new Error(
      `Key rotation failed: could not re-wrap key for ${reWrapFailures.length} recipient(s). ` +
        'Aborting to prevent inconsistent state.'
    );
  }

  // 4. Hard-delete all revoked shares for this folder
  for (const revoked of revokedForFolder) {
    try {
      await completeShareRotation(revoked.shareId);
    } catch (err) {
      logger.warn(`[share] Failed to complete rotation for share ${revoked.shareId}:`, err);
    }
  }

  // 5. Invalidate the sent shares cache so next check fetches fresh state
  useShareStore.getState().setSentShares([]);

  return { newFolderKey };
}
