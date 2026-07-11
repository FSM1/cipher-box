/**
 * @cipherbox/sdk - Share operations
 *
 * Extracted from: apps/web/src/services/share.service.ts (468 LOC)
 * All Zustand store access replaced with explicit parameters.
 *
 * Share operations handle user-to-user sharing via ECIES key wrapping:
 * - createShare: wrap folder/file key with recipient's public key
 * - revokeShare: soft-delete a share via API
 *
 * The API client functions are called directly for server communication.
 * No store dependencies -- all state passed as explicit params.
 */

import { wrapKey, bytesToHex } from '@cipherbox/crypto';
import type { SdkContext } from '@cipherbox/sdk-core';
import { isNonRetryableError } from '../error';

/**
 * Max IPNS names per revoke-for-items request. Mirrors the server-side
 * `@ArrayMaxSize(5000)` guard on RevokeForItemsDto — a larger subtree is split
 * into sequential batches so the request never trips that validation cap.
 */
const REVOKE_BATCH_SIZE = 5000;

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

/**
 * Bulk hard-revoke every share/invite the caller created for ANY of the given
 * IPNS names, with a couple of retries.
 *
 * Used when deleting a file/folder subtree to the recycle bin: the access cutoff
 * MUST land before the eventual empty-bin unpin, or a still-shared content CID
 * would orphan the sharee. This is therefore a fail-closed step — the caller
 * (addToBin) aborts the delete if it ultimately fails.
 *
 * The actual API call (POST /shares/revoke-for-items) is injected so this stays
 * mockable at the boundary and free of api-client coupling.
 *
 * The list is chunked into batches of {@link REVOKE_BATCH_SIZE} (matching the
 * server's `@ArrayMaxSize` cap) and revoked sequentially — every batch must
 * succeed before the next is attempted, preserving the fail-closed contract for
 * subtrees larger than a single request can carry.
 *
 * @param params.ipnsNames - Every node ipnsName in the deleted subtree.
 * @param params.revokeFn - Issues the authed backend call; resolves on success.
 * @param params.maxAttempts - Total attempts per batch (default 3: 1 + 2 retries).
 */
export async function revokeSharesForItems(params: {
  ipnsNames: string[];
  revokeFn: (ipnsNames: string[]) => Promise<void>;
  maxAttempts?: number;
}): Promise<void> {
  if (params.ipnsNames.length === 0) return;
  const maxAttempts = params.maxAttempts ?? 3;
  for (let start = 0; start < params.ipnsNames.length; start += REVOKE_BATCH_SIZE) {
    const batch = params.ipnsNames.slice(start, start + REVOKE_BATCH_SIZE);
    await revokeBatchWithRetry(batch, params.revokeFn, maxAttempts);
  }
}

/**
 * Revoke a single ≤REVOKE_BATCH_SIZE batch with bounded retries. A deterministic
 * client failure (4xx — e.g. a validation 400 or an auth 401/403) is rethrown
 * immediately since it will never succeed on retry; only transient errors
 * (5xx/network) consume the backoff budget.
 */
async function revokeBatchWithRetry(
  ipnsNames: string[],
  revokeFn: (ipnsNames: string[]) => Promise<void>,
  maxAttempts: number
): Promise<void> {
  let lastErr: unknown;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      await revokeFn(ipnsNames);
      return;
    } catch (err) {
      lastErr = err;
      // Non-retryable 4xx: surface immediately rather than burning backoff.
      if (isNonRetryableError(err)) break;
      if (attempt < maxAttempts - 1) {
        await new Promise((r) => setTimeout(r, 300 * Math.pow(2, attempt)));
      }
    }
  }
  throw lastErr instanceof Error
    ? lastErr
    : new Error('Failed to revoke shares for deleted items', { cause: lastErr });
}

// Shared-write operations (stateless functions for write-share recipients)
export {
  uploadToSharedFolder,
  createSharedSubfolder,
  renameInSharedFolder,
  deleteFromSharedFolder,
  updateSharedFile,
  moveInSharedFolder,
  CannotWriteUntilRefetchError,
  type SharedWriteContext,
} from './shared-write';

// Shared write context builder
export { buildSharedWriteContext, type SharedWriteContextParams } from './context';

// Share key cache
export { ShareKeyCache, type CachedShareKey } from './key-cache';

// Owner-reconcile driver (D-10/D-11) -- drives sdk-core's reMintGrantsRootedAt
// with callbacks assembled from an injected transport. apps/web supplies the
// concrete api-client transport (68-07 owner-reconcile.service.ts).
export {
  buildGrantRemintCallbacks,
  runOwnerReconcile,
  type OwnerReconcileTransport,
  type GrantRow,
} from './owner-reconcile';
