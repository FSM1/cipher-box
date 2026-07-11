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

import type { SealedChildRef, PublishedNode } from '@cipherbox/core';
import { hexToBytes } from '@cipherbox/crypto';
import type { CipherBoxClient, SharedFolderState } from '@cipherbox/sdk';

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
  | 'getSharedFolderState' // Plan 09 (68.2-09): raw-identity re-read on projection apply
>;

/**
 * Placeholder PublishedNode used when Phase-68 wiring has not yet supplied the
 * real published envelope. The write-body operations in Phase 65 are not yet
 * exercised through real navigation paths; Phase 68 will replace this with the
 * actual resolved node.
 */
export const PLACEHOLDER_PUBLISHED_NODE: PublishedNode = {
  schema: 'node/v3',
  kind: 'folder',
  id: '00000000-0000-0000-0000-000000000000',
  generation: 0,
  aeadVersion: 1,
  readSealed: '',
};

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
  /**
   * 32-byte AES key for unsealing the write-body (Phase 65 write-body model).
   * Supplied by Phase-68 wiring; defaults to a zero key placeholder until then.
   */
  writeKey?: Uint8Array;
  /**
   * Current on-wire published envelope for unsealing the write-body.
   * Supplied by Phase-68 wiring; defaults to a sentinel placeholder until then.
   */
  publishedNode?: PublishedNode;
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
    writeKey: args.writeKey ?? new Uint8Array(32),
    publishedNode: args.publishedNode ?? PLACEHOLDER_PUBLISHED_NODE,
    sequenceNumber: args.sequenceNumber,
    children: args.children,
    ownerPublicKey: args.ownerPublicKey,
    recipientPublicKey: args.recipientPublicKey,
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
 * `event.children` is the SDK's resolved `ResolvedChild[]` DISPLAY listing
 * (68.2-02) -- it no longer carries the raw `SealedChildRef[]` identity
 * `apply`'s write-path consumers need (readKeySealed/generation/
 * versionFloor). The raw children are re-read from the SDK's authoritative
 * `sharedFolderTree` via `getSharedFolderState` at event time instead (Plan
 * 09, SC#3: the web never independently resolves; it only re-reads the
 * SDK's own already-current state).
 *
 * Note: `updateSharedFile` emits with UNCHANGED sequence (file-only
 * metadata publish) — the projection applies it as a no-op-on-data
 * re-resolve signal, which is safe because the raw children are identical.
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
    const activeShareId = getActiveShareId();
    if (event.shareId !== activeShareId) return;
    const state = client.getSharedFolderState(activeShareId);
    apply(state?.children ?? [], event.sequenceNumber);
  });
}
