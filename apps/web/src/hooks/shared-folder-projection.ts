/**
 * shared-folder-projection -- Pure helpers wiring the web shared-folder hooks to
 * the SDK's sharedFolderTree (REQ-3, phase 48).
 *
 * The SDK client (`@cipherbox/sdk`) is the single owner of shared-folder write
 * state. The web hooks must:
 *  1. Seed the SDK with the resolved share context on share/subfolder entry
 *     (`seedSharedFolder` -> `client.loadSharedFolder`).
 *  2. Treat `folderChildrenRef`/`sequenceNumberRef` as PROJECTIONS fed only by
 *     the `sharedFolder:updated` event (`subscribeSharedFolderProjection`).
 *
 * Both helpers are framework-agnostic so they can be unit-tested in the web
 * vitest `node` environment (no React render harness available — mirrors the
 * owned-path `folder.store` projection tests).
 */

import type { SealedChildRef } from '@cipherbox/core';
import { hexToBytes } from '@cipherbox/crypto';
import type { CipherBoxClient, SharedFolderState, ShareKeyType } from '@cipherbox/sdk';

/** Parse a 0x-prefixed or bare hex public key string into bytes. */
export function parsePublicKey(keyHex: string): Uint8Array {
  // hexToBytes already strips an optional 0x prefix.
  return hexToBytes(keyHex);
}

/** The minimal client surface these helpers depend on (eases mocking in tests). */
export type SharedFolderClient = Pick<
  CipherBoxClient,
  | 'on'
  | 'loadSharedFolder'
  | 'unloadSharedFolder'
  | 'uploadToSharedFolder'
  | 'createSharedSubfolder'
  | 'renameInSharedFolder'
  | 'deleteFromSharedFolder'
  | 'updateSharedFile'
  | 'moveInSharedFolder' // REQ-2
  | 'enumerateSharedSubtree' // REQ-1
>;

/** Inputs needed to seed (or re-seed) the SDK for the active shared folder. */
export type SeedSharedFolderArgs = {
  shareId: string;
  ipnsName: string;
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  sequenceNumber: bigint;
  children: SealedChildRef[];
  ownerPublicKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  addShareKeysFn: (
    shareId: string,
    keys: Array<{ keyType: ShareKeyType; itemId: string; encryptedKey: string }>
  ) => Promise<void>;
};

/**
 * Seed / re-seed the SDK's sharedFolderTree for the active shared folder.
 *
 * The SDK keys shared state by `shareId`, but the web navigates through
 * subfolders within a single share — each with a distinct ipnsName / folderKey /
 * ipnsPrivateKey / sequence. So this is invoked on EVERY navigation point that
 * changes the active folder context (share-enter, subfolder-enter, up,
 * breadcrumb), overwriting the prior depth's state under the same shareId.
 *
 * `SharedFolderTree.set()` clones the key buffers, so the caller's `folderKey` /
 * `ipnsPrivateKey` buffers are never zeroed by the SDK.
 */
export function seedSharedFolder(client: SharedFolderClient, args: SeedSharedFolderArgs): void {
  const state: SharedFolderState = {
    shareId: args.shareId,
    ipnsName: args.ipnsName,
    folderKey: args.folderKey,
    ipnsPrivateKey: args.ipnsPrivateKey,
    sequenceNumber: args.sequenceNumber,
    children: args.children,
    ownerPublicKey: args.ownerPublicKey,
    recipientPublicKey: args.recipientPublicKey,
    addShareKeysFn: args.addShareKeysFn,
  };
  client.loadSharedFolder(args.shareId, state);
}

/** Callback shape for the projection: receives the SDK's authoritative state. */
export type SharedFolderProjectionApply = (
  children: SealedChildRef[],
  sequenceNumber: bigint
) => void;

/**
 * Subscribe to `sharedFolder:updated` and project the SDK's authoritative
 * children + sequence into the web refs/state — the ONLY writer of those refs
 * post-mutation (T-48-09). Events for a different shareId than the active one
 * are ignored (T-48-10: no cross-share state bleed at the projection layer).
 *
 * `getActiveShareId` is read at event time (not closed over) so the same
 * subscription stays correct as the active share changes.
 *
 * Note: `updateSharedFile` emits with UNCHANGED children/sequence (file-only
 * metadata publish) — the projection applies it as a no-op-on-data re-resolve
 * signal, which is safe because children/sequence are identical.
 *
 * @returns the unsubscribe function (call on unmount / share-change).
 */
export function subscribeSharedFolderProjection(
  client: SharedFolderClient,
  getActiveShareId: () => string | null,
  apply: SharedFolderProjectionApply
): () => void {
  return client.on((event) => {
    if (event.type !== 'sharedFolder:updated') return;
    if (event.shareId !== getActiveShareId()) return;
    apply(event.children, event.sequenceNumber);
  });
}
