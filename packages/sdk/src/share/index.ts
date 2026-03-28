/**
 * @cipherbox/sdk - Share operations
 *
 * Extracted from: apps/web/src/services/share.service.ts (468 LOC)
 * All Zustand store access replaced with explicit parameters.
 *
 * Share operations handle user-to-user sharing via ECIES key wrapping:
 * - createShare: wrap folder/file key with recipient's public key
 * - revokeShare: soft-delete a share via API
 * - reWrapForRecipients: after adding items to shared folder, re-wrap keys
 *
 * The API client functions are called directly for server communication.
 * No store dependencies -- all state passed as explicit params.
 */

import { wrapKey, bytesToHex, hexToBytes } from '@cipherbox/crypto';
import type { SdkContext } from '@cipherbox/sdk-core';

/** Re-export the canonical share key type for consumers */
export type { ShareKeyType } from './shared-write';

/**
 * Context for share operations. Replaces Zustand store access.
 */
export type ShareOperationContext = {
  ctx: SdkContext;
  userPrivateKey: Uint8Array;
  userPublicKey: Uint8Array;
};

/**
 * A sent share record (simplified from store type).
 */
export type SentShareInfo = {
  shareId: string;
  recipientPublicKey: string;
  itemType: 'folder' | 'file';
  ipnsName: string;
  itemName: string;
};

/**
 * Create a new share by wrapping the folder/file key with the recipient's
 * public key via ECIES.
 *
 * This is the core share creation logic. The actual API call to create the
 * share record on the server should be handled by the consumer or via
 * the api-client directly.
 *
 * @param params.folderKey - Decrypted AES-256 key for the shared item
 * @param params.recipientPublicKey - Recipient's secp256k1 public key
 * @param params.folderIpnsName - IPNS name of the shared folder
 * @param params.shareCtx - Share operation context
 * @returns Hex-encoded ECIES-wrapped key for the recipient
 */
export async function createShareKey(params: {
  folderKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  folderIpnsName: string;
  shareCtx: ShareOperationContext;
}): Promise<{ encryptedKey: string }> {
  // Wrap the folder key with recipient's public key via ECIES
  const wrappedKey = await wrapKey(params.folderKey, params.recipientPublicKey);
  return { encryptedKey: bytesToHex(wrappedKey) };
}

/**
 * Re-wrap keys for all share recipients after adding new items to a shared folder.
 *
 * For each existing share covering the folder, wraps each new item's key
 * with the share recipient's public key.
 *
 * This is a fire-and-forget operation -- individual failures are collected
 * but don't block the overall operation.
 *
 * @param params.coveringShares - Active shares that cover this folder
 * @param params.newItems - New items whose keys need re-wrapping
 * @returns List of failed recipient public keys
 */
export async function reWrapForRecipients(params: {
  coveringShares: SentShareInfo[];
  newItems: Array<{
    keyType: 'file' | 'folder';
    itemId: string;
    plaintextKey: Uint8Array;
  }>;
  addShareKeysFn: (
    shareId: string,
    keys: Array<{ keyType: 'file' | 'folder'; itemId: string; encryptedKey: string }>
  ) => Promise<void>;
}): Promise<{ failedRecipients: string[] }> {
  if (params.coveringShares.length === 0) return { failedRecipients: [] };

  const failedRecipients: string[] = [];

  for (const share of params.coveringShares) {
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

      await params.addShareKeysFn(share.shareId, wrappedKeys);
    } catch {
      failedRecipients.push(share.recipientPublicKey);
    }
  }

  return { failedRecipients };
}

/**
 * Revoke a share (soft-delete).
 *
 * This is a thin wrapper that calls the provided revoke function.
 * The actual API call is handled by the consumer or api-client.
 *
 * @param params.shareId - Share ID to revoke
 * @param params.revokeShareFn - Function to call the API revoke endpoint
 */
export async function revokeShare(params: {
  shareId: string;
  revokeShareFn: (shareId: string) => Promise<void>;
}): Promise<void> {
  await params.revokeShareFn(params.shareId);
}

// Shared-write operations (stateless functions for write-share recipients)
export {
  uploadToSharedFolder,
  createSharedSubfolder,
  renameInSharedFolder,
  deleteFromSharedFolder,
  updateSharedFile,
  updateSharePermission,
  type SharedWriteContext,
} from './shared-write';

// Shared write context builder
export { buildSharedWriteContext, type SharedWriteContextParams } from './context';

// Share key cache
export { ShareKeyCache, type CachedShareKey } from './key-cache';
