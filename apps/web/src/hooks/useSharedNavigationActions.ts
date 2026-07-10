/**
 * useSharedNavigationActions -- Navigation action handlers for shared content.
 *
 * Wires the shared-folder read-chain (Node v3): navigateToShare /
 * navigateToSubfolder descend via the SDK's gated shared read-chain facade
 * (`client.resolveShareRoot` / `client.descendSharedChild`, 68.2-08) -- the
 * web no longer runs its own read-chain walk (the walk lives in the SDK,
 * hoisted in Plan 02/08, gated behind ROT-07 per Plan 01). navigateUp /
 * navigateToBreadcrumb restore prior levels from the in-memory nav stack (no
 * network round-trip). downloadSharedFile / loadSharedFileContent route
 * through `client.downloadSharedFile` (68.2-08), which wraps sdk-core's
 * navigateReadChain + the fetch/decrypt orchestration entirely inside the SDK.
 *
 * Security (D-09): recipient vault private key is caller-owned, never zeroed
 * here. Minted intermediates (share-root/subfolder readKeys) are zeroed on
 * every exit path once they are no longer the live state.
 *
 * Zeroization audit (73-07, SC1): the nav stack now retains a `writeKey` per
 * depth (`NavStackEntry.writeKey`) and an active-depth `currentWriteKeyRef`
 * (mirroring `ipnsPrivateKeyRef`), extending a key buffer's in-memory
 * lifetime. Every exit path is covered:
 *  - New-share entry (`navigateToShare`): `zeroWriteKey()` releases any
 *    prior active-depth buffer before the new clone is stored.
 *  - Descent (`navigateToSubfolder`): the pushed stack entry TRANSFERS the
 *    prior active-depth buffer (no clone, no zero -- the stack entry is now
 *    the sole owner); the new child depth gets a fresh clone.
 *  - Restore (`restoreToBreadcrumbIndex`, shared by `navigateUp` /
 *    `navigateToBreadcrumb`): the abandoned active-depth buffer is zeroed
 *    via `zeroWriteKey()`; every discarded deeper stack entry's `writeKey` is
 *    `.fill(0)`'d alongside its `folderKey`; the restored target's buffer is
 *    TRANSFERRED (not cloned) into `currentWriteKeyRef`.
 *  - Root (`navigateToRoot`): every stack entry's `writeKey` is `.fill(0)`'d
 *    alongside its `folderKey`, and `zeroWriteKey()` releases the active
 *    depth's buffer.
 *  - Unmount: `zeroWriteKey()` is called from `useSharedNavigation.ts`'s
 *    cleanup, mirroring `zeroIpnsKey()`.
 * `seedActiveSharedFolder` clones `writeKey` internally (shared-folder-
 * projection.ts), so a retained buffer passed to it is never zeroed by the
 * seed call itself -- no use-after-free.
 */

import { useCallback, type MutableRefObject } from 'react';
import type { SealedChildRef, PublishedNode } from '@cipherbox/core';
import { unwrapKey, hexToBytes } from '@cipherbox/crypto';
import { useShareStore } from '../stores/share.store';
import { useAuthStore } from '../stores/auth.store';
import { hideShare } from '../services/share.service';
import { triggerBrowserDownload } from '../services/download.service';
import { getSdkClient } from '../lib/sdk-provider';
import { logger } from '../lib/logger';
import {
  parsePublicKey,
  PLACEHOLDER_PUBLISHED_NODE,
  type SeedSharedFolderArgs,
} from './shared-folder-projection';
import type { SharedListItem, SharedBreadcrumb } from './useSharedNavigation';

type NavStackEntry = {
  folderId: string;
  folderName: string;
  children: SealedChildRef[];
  folderKey: Uint8Array;
  /** This depth's writeKey (73-07, SC1) -- null for read-only shares/depths. */
  writeKey: Uint8Array | null;
  /**
   * This depth's on-wire published envelope (73-07, SC1 correctness fix).
   * Write ops (`uploadToSharedFolder` et al.) trust `SharedFolderState.
   * publishedNode` directly (client.ts `buildSharedWriteContextFromState`) --
   * they do NOT re-resolve it from the network. Without restoring this
   * alongside the writeKey, `seedActiveSharedFolder` falls back to
   * `PLACEHOLDER_PUBLISHED_NODE` (shared-folder-projection.ts) after a
   * restore, and the very first write at the restored depth fails to unseal
   * ("Decryption failed") even with the correct writeKey.
   */
  publishedNode: PublishedNode;
  ipnsName: string;
  sequenceNumber: bigint | null;
};

export type SharedNavigationActionsParams = {
  sharedItems: SharedListItem[];
  folderChildren: SealedChildRef[];
  folderKey: Uint8Array | null;
  breadcrumbs: SharedBreadcrumb[];
  currentShareId: string | null;
  permission: 'read' | 'write' | null;
  ipnsName: string | null;
  currentSequenceNumber: bigint | null;
  currentView: 'list' | 'folder' | 'file';
  // Refs
  folderChildrenRef: MutableRefObject<SealedChildRef[]>;
  sequenceNumberRef: MutableRefObject<bigint | null>;
  ipnsPrivateKeyRef: MutableRefObject<Uint8Array | null>;
  /** Active-depth writeKey (73-07, SC1) -- mirrors ipnsPrivateKeyRef. */
  currentWriteKeyRef: MutableRefObject<Uint8Array | null>;
  navStackRef: MutableRefObject<NavStackEntry[]>;
  // State setters
  setCurrentView: (view: 'list' | 'folder' | 'file') => void;
  setCurrentShareId: (id: string | null) => void;
  setFolderChildren: (children: SealedChildRef[]) => void;
  setFolderKey: (key: Uint8Array | null) => void;
  setBreadcrumbs: (
    crumbs: SharedBreadcrumb[] | ((prev: SharedBreadcrumb[]) => SharedBreadcrumb[])
  ) => void;
  setPermission: (perm: 'read' | 'write' | null) => void;
  setIpnsName: (name: string | null) => void;
  setCurrentSequenceNumber: (seq: bigint | null) => void;
  setIsLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setSharedItems: (updater: (prev: SharedListItem[]) => SharedListItem[]) => void;
  // Helpers from orchestrator
  clearPolling: () => void;
  zeroIpnsKey: () => void;
  /** Zero + null out currentWriteKeyRef (73-07, SC1) -- mirrors zeroIpnsKey. */
  zeroWriteKey: () => void;
  /**
   * Seed (or re-seed) the SDK's sharedFolderTree for the active depth.
   */
  seedActiveSharedFolder: (args: Omit<SeedSharedFolderArgs, 'addShareKeysFn'>) => void;
};

/**
 * Unwrap a grant's `encryptedWriteKey` into the shared-root writeKey
 * (68.1-20, SHARE-WRITE-KEY recipient side).
 *
 * Only meaningful for the share ROOT: a node's writeKey under the node/v3
 * write-chain is sealed inside its PARENT's write-body (`WriteChildRef.
 * writeKeySealed`), so the encrypted-key grant only ever carries the
 * shared item's OWN root writeKey -- there is no equivalent per-subfolder
 * encrypted key to unwrap deeper in the tree (that requires a write-chain walk
 * from this root writeKey, out of this helper's scope -- see client.ts
 * `moveInSharedFolder`, 68.1-20 Task 3).
 *
 * Returns `null` for read-only grants (no `encryptedWriteKey`) so callers
 * preserve the existing zero-buffer `writeKey` seed default untouched
 * (T-68.1-20-01: a read-only grant can never recover a usable writeKey).
 */
async function resolveSharedRootWriteKey(
  encryptedWriteKey: string | null | undefined,
  vaultPrivateKey: Uint8Array
): Promise<Uint8Array | null> {
  if (!encryptedWriteKey) return null;
  return unwrapKey(hexToBytes(encryptedWriteKey), vaultPrivateKey);
}

export function useSharedNavigationActions(p: SharedNavigationActionsParams) {
  /**
   * Navigate into a shared folder/file from the top-level list.
   *
   * `client.resolveShareRoot` performs the ONE ECIES unwrap of
   * `encryptedReadKey` -> share-root readKey and resolves + unseals the
   * root Node entirely inside the SDK (D-07). A `kind: 'file'` root
   * (single-file share) switches to `currentView: 'file'` instead --
   * `SharedFileBrowser`'s effect then calls `downloadSharedFile` with a
   * synthetic root-referencing ref.
   */
  const navigateToShare = useCallback(
    async (shareId: string) => {
      const shareEntry = p.sharedItems.find((s) => s.share.shareId === shareId);
      if (!shareEntry) {
        p.setError('Shared item not found');
        return;
      }
      const share = shareEntry.share;
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) {
        p.setError('Not authenticated');
        return;
      }
      const vaultKeypair = auth.vaultKeypair;

      p.setIsLoading(true);
      p.setError(null);

      let committed = false;
      // D-09: recipient private key is caller-owned -- never zeroed by this
      // handler. Held nullable so the finally can zero the SDK-minted read
      // key if an exception occurs after 'ok' but before it is either
      // stored into state (folder case) or explicitly discarded (file case).
      let shareRootReadKey: Uint8Array | null = null;

      try {
        const result = await getSdkClient().resolveShareRoot({
          encryptedReadKey: share.encryptedReadKey,
          recipientPrivateKey: vaultKeypair.privateKey,
          shareRootIpnsName: share.ipnsName,
          rootExpectedGeneration: share.rootGeneration,
        });

        if (result.status === 'revoked') {
          p.setError('Share is no longer available (revoked)');
          return;
        }
        if (result.status === 'behind-retry') {
          p.setError('This share was updated -- please reopen it');
          return;
        }

        const { kind, readKey, children, sequenceNumber: rootSeq } = result;
        shareRootReadKey = readKey;

        p.navStackRef.current = [];
        p.setCurrentShareId(shareId);
        p.setPermission(share.permission);

        if (kind === 'file') {
          // Single-file share: the root IS the leaf. Discard the readKey we
          // minted to determine the kind -- downloadSharedFile independently
          // re-derives the full chain via client.downloadSharedFile (path: []).
          shareRootReadKey.fill(0);
          p.setFolderChildren([]);
          p.setFolderKey(null);
          p.setIpnsName(null);
          p.setCurrentSequenceNumber(null);
          p.setBreadcrumbs([]);
          p.setCurrentView('file');
          committed = true;
          return;
        }

        const ipnsPrivateKey = new Uint8Array(32);

        p.zeroIpnsKey();
        p.ipnsPrivateKeyRef.current = ipnsPrivateKey;
        p.setIpnsName(share.ipnsName);
        p.setCurrentSequenceNumber(rootSeq);
        p.setFolderChildren(children);
        p.setFolderKey(shareRootReadKey);
        p.setBreadcrumbs([{ id: share.rootNodeId, name: share.itemName }]);
        p.setCurrentView('folder');
        committed = true;

        // T-68.1-20-01: recover the shared-root writeKey from the grant's
        // encryptedWriteKey (write grants only) -- read-only grants keep the
        // SDK's zero-buffer writeKey default (cannot unseal the write-body).
        // Navigation is already committed above, so a write-key failure must NOT
        // surface as a navigation error -- guard the lookup and fall back to
        // read-only (the zero-buffer writeKey seed default keeps write ops gated)
        // rather than hitting the outer catch.
        let shareRootWriteKey: Uint8Array | null = null;
        try {
          shareRootWriteKey = await resolveSharedRootWriteKey(
            share.encryptedWriteKey,
            vaultKeypair.privateKey
          );
        } catch (writeKeyErr) {
          logger.error(
            '[SharedNav] Failed to recover shared-root write key (continuing read-only):',
            writeKeyErr
          );
        }
        // 73-07 SC1: this is a NEW share entry, so any prior active-depth
        // writeKey is abandoned -- release it before storing the clone for
        // this (root) depth.
        p.zeroWriteKey();
        p.currentWriteKeyRef.current = shareRootWriteKey ? new Uint8Array(shareRootWriteKey) : null;
        try {
          p.seedActiveSharedFolder({
            shareId,
            ipnsName: share.ipnsName,
            folderKey: shareRootReadKey,
            ipnsPrivateKey,
            writeKey: shareRootWriteKey ?? undefined,
            sequenceNumber: rootSeq,
            children,
            ownerPublicKey: parsePublicKey(share.sharerPublicKey),
            recipientPublicKey: vaultKeypair.publicKey,
            publishedNode: result.published,
          });
        } finally {
          // D-09: seedSharedFolder clones the writeKey buffer internally
          // (shared-folder-projection.ts) -- this call's own derived buffer
          // is the terminal owner and must be zeroed here (currentWriteKeyRef
          // holds an independent clone, so it survives this zero).
          shareRootWriteKey?.fill(0);
        }
      } catch (err) {
        logger.error('[SharedNav] Failed to navigate to share:', err);
        p.setError('Failed to open shared item');
      } finally {
        // shareRootReadKey is zeroed inside the SDK on every non-'ok' result
        // (revoked/behind-retry); once 'ok', the web is the terminal owner.
        // `committed` is set true immediately once the key is either stored
        // into state (folder case) or explicitly discarded (file case) --
        // this only fires if something throws in between, preventing a leak.
        if (!committed && shareRootReadKey) shareRootReadKey.fill(0);
        p.setIsLoading(false);
      }
    },
    [p.sharedItems, p.seedActiveSharedFolder, p.zeroIpnsKey, p.zeroWriteKey]
  );

  /**
   * Navigate into a subfolder within a shared folder.
   *
   * One read-chain hop via `client.descendSharedChild` -- gated-resolve the
   * target's SealedChildRef, unseal its readKey under the CURRENT folderKey
   * (generation-source rule handled inside the SDK), unseal the child Node
   * to recover its own children, all inside the SDK (D-07).
   */
  const navigateToSubfolder = useCallback(
    async (folderId: string, folderName: string) => {
      const currentFolderKey = p.folderKey;
      const currentShareId = p.currentShareId;
      const currentIpnsName = p.ipnsName;
      if (!currentFolderKey || !currentShareId || !currentIpnsName) {
        p.setError('Not available');
        return;
      }
      const childRef = p.folderChildren.find((c) => c.ipnsName === folderId);
      if (!childRef) {
        p.setError('Item not found');
        return;
      }
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) {
        p.setError('Not authenticated');
        return;
      }
      const vaultKeypair = auth.vaultKeypair;

      p.setIsLoading(true);
      p.setError(null);

      try {
        const descended = await getSdkClient().descendSharedChild(childRef, currentFolderKey);
        if (!descended) {
          p.setError('Folder is no longer available (revoked)');
          return;
        }
        const { readKey: childReadKey, children, sequenceNumber: childSeq, published } = descended;

        let committed = false;
        try {
          const shareEntry = p.sharedItems.find((s) => s.share.shareId === currentShareId);
          if (!shareEntry) {
            p.setError('Shared item not found');
            return;
          }
          const ipnsPrivateKey = new Uint8Array(32);

          // 73-07 SC1 correctness fix: capture the CURRENT (pre-descent)
          // depth's live publishedNode from the SDK's sharedFolderTree BEFORE
          // it gets overwritten below by the child's seedActiveSharedFolder
          // call -- write ops (uploadToSharedFolder et al.) trust
          // SharedFolderState.publishedNode directly (no network re-resolve),
          // so restoring this depth later without its real publishedNode
          // would seed the placeholder and fail every write (see
          // NavStackEntry.publishedNode doc).
          const currentPublishedNode =
            getSdkClient().getSharedFolderState(currentShareId)?.publishedNode;

          // Push the CURRENT (pre-descent) level so navigateUp / navigateToBreadcrumb
          // can restore it without a network round-trip. 73-07 SC1: TRANSFER
          // the active-depth writeKey into the pushed entry -- the stack
          // entry becomes its sole owner, so it is NOT zeroed here.
          p.navStackRef.current = [
            ...p.navStackRef.current,
            {
              folderId: currentIpnsName,
              folderName: p.breadcrumbs[p.breadcrumbs.length - 1]?.name ?? '',
              children: p.folderChildren,
              folderKey: currentFolderKey,
              writeKey: p.currentWriteKeyRef.current,
              // Fallback should be unreachable (the current depth is always
              // seeded before a descent), but never regress to a hard crash.
              publishedNode: currentPublishedNode ?? PLACEHOLDER_PUBLISHED_NODE,
              ipnsName: currentIpnsName,
              sequenceNumber: p.currentSequenceNumber,
            },
          ];
          p.currentWriteKeyRef.current = null;

          p.zeroIpnsKey();
          p.ipnsPrivateKeyRef.current = ipnsPrivateKey;
          p.setFolderChildren(children);
          p.setFolderKey(childReadKey);
          p.setIpnsName(childRef.ipnsName);
          p.setCurrentSequenceNumber(childSeq);
          p.setBreadcrumbs((prev) => [...prev, { id: childRef.ipnsName, name: folderName }]);
          p.setCurrentView('folder');
          committed = true;

          // 68.1-30: recover this subfolder's writeKey from the PARENT depth's
          // write-body chain BEFORE re-seeding sharedFolderTree to the child --
          // resolveSharedSubfolderWriteKey reads sharedFolderTree.get(shareId),
          // which is still the parent depth until seedActiveSharedFolder below
          // overwrites that entry. Closes the deep-shared-write gap (WEB-03,
          // writable-shares 8.2): previously every descent seeded a zero
          // writeKey below the share root, failing GCM auth on any write op.
          const childWriteKey = await getSdkClient().resolveSharedSubfolderWriteKey(
            currentShareId,
            { published, readKey: childReadKey, generation: childRef.generation }
          );
          // 73-07 SC1: the new active depth (the child) gets a fresh clone --
          // currentWriteKeyRef.current was already nulled above (transferred
          // to the pushed stack entry), so this is a plain assignment.
          p.currentWriteKeyRef.current = childWriteKey ? new Uint8Array(childWriteKey) : null;
          try {
            p.seedActiveSharedFolder({
              shareId: currentShareId,
              ipnsName: childRef.ipnsName,
              folderKey: childReadKey,
              ipnsPrivateKey,
              writeKey: childWriteKey ?? undefined,
              sequenceNumber: childSeq,
              children,
              ownerPublicKey: parsePublicKey(shareEntry.share.sharerPublicKey),
              recipientPublicKey: vaultKeypair.publicKey,
              publishedNode: published,
            });
          } finally {
            // D-09: seedSharedFolder clones the writeKey buffer internally
            // (shared-folder-projection.ts) -- this call's own derived buffer
            // is the terminal owner and must be zeroed here (mirrors
            // navigateToShare's shareRootWriteKey finally; currentWriteKeyRef
            // holds an independent clone, so it survives this zero).
            childWriteKey?.fill(0);
          }
        } finally {
          if (!committed) childReadKey.fill(0);
        }
      } catch (err) {
        logger.error('[SharedNav] Failed to navigate to subfolder:', err);
        p.setError('Failed to open folder');
      } finally {
        p.setIsLoading(false);
      }
    },
    [
      p.folderKey,
      p.folderChildren,
      p.currentShareId,
      p.ipnsName,
      p.breadcrumbs,
      p.currentSequenceNumber,
      p.permission,
      p.sharedItems,
      p.seedActiveSharedFolder,
      p.zeroIpnsKey,
    ]
  );

  /**
   * Navigate back to the top-level shared list.
   */
  const navigateToRoot = useCallback(() => {
    if (p.folderKey) p.folderKey.fill(0);
    for (const entry of p.navStackRef.current) {
      entry.folderKey.fill(0);
      entry.writeKey?.fill(0);
    }
    p.zeroIpnsKey();
    p.zeroWriteKey();
    p.clearPolling();
    p.setCurrentView('list');
    p.setCurrentShareId(null);
    p.setFolderChildren([]);
    p.setFolderKey(null);
    p.setBreadcrumbs([]);
    p.setPermission(null);
    p.setIpnsName(null);
    p.setCurrentSequenceNumber(null);
    p.navStackRef.current = [];
    p.setError(null);
  }, [p.folderKey, p.zeroIpnsKey, p.zeroWriteKey, p.clearPolling]);

  /**
   * Restore navigation state to a specific breadcrumb/nav-stack index.
   *
   * The single restore helper shared by `navigateUp` (called with
   * `stack.length - 1`) and `navigateToBreadcrumb` (called with the target
   * `crumbIndex`) -- Phase 73 SC6 consolidation of what were previously two
   * near-verbatim ~55-line blocks. Truncates the nav stack to `crumbIndex`,
   * zeroing the folderKeys (and writeKeys, 73-07 SC1) of every discarded
   * deeper level (including the current live level), restores the target
   * entry's children/folderKey/writeKey/ipnsName/sequenceNumber/breadcrumbs,
   * and re-seeds the SDK's sharedFolderTree via `seedActiveSharedFolder`.
   *
   * SC1 (73-07): the target entry's stored `writeKey` is TRANSFERRED into
   * `currentWriteKeyRef` (not re-derived) -- root is just the first stack
   * entry, no special case. This replaces the prior `isRootDepth` /
   * `resolveSharedRootWriteKey` re-derivation, which only ever restored write
   * capability for a root-depth landing and silently seeded a zero-buffer
   * writeKey for any deeper restore (the exact WEB-03/SC1 gap).
   */
  const restoreToBreadcrumbIndex = useCallback(
    async (crumbIndex: number) => {
      const stack = p.navStackRef.current;
      if (crumbIndex < 0 || crumbIndex >= stack.length) return;
      const target = stack[crumbIndex];
      const currentShareId = p.currentShareId;

      // Discard the level(s) being left: the current live folderKey/writeKey
      // plus any deeper stack entries beyond crumbIndex (empty range for
      // navigateUp's one-level-up case, since crumbIndex is always the top
      // of stack there). The active depth's writeKey is abandoned on the way
      // up -- zero it via zeroWriteKey() before it is overwritten below.
      if (p.folderKey) p.folderKey.fill(0);
      p.zeroWriteKey();
      for (let i = crumbIndex + 1; i < stack.length; i++) {
        stack[i].folderKey.fill(0);
        stack[i].writeKey?.fill(0);
      }
      p.navStackRef.current = stack.slice(0, crumbIndex);

      p.setFolderChildren(target.children);
      p.setFolderKey(target.folderKey);
      p.setIpnsName(target.ipnsName);
      p.setCurrentSequenceNumber(target.sequenceNumber);
      p.setBreadcrumbs((prev) => prev.slice(0, crumbIndex + 1));

      // SC1: transfer (not clone) the restored target's writeKey into the
      // active-depth ref -- currentWriteKeyRef becomes its sole owner. Never
      // zeroed in a finally below: it is retained state, not a throwaway
      // derivation.
      p.currentWriteKeyRef.current = target.writeKey;

      const auth = useAuthStore.getState();
      if (!currentShareId || !auth.vaultKeypair) return;
      const vaultKeypair = auth.vaultKeypair;

      try {
        const shareEntry = p.sharedItems.find((s) => s.share.shareId === currentShareId);
        if (!shareEntry) return;
        const ipnsPrivateKey = new Uint8Array(32);
        p.zeroIpnsKey();
        p.ipnsPrivateKeyRef.current = ipnsPrivateKey;

        p.seedActiveSharedFolder({
          shareId: currentShareId,
          ipnsName: target.ipnsName,
          folderKey: target.folderKey,
          ipnsPrivateKey,
          writeKey: p.currentWriteKeyRef.current ?? undefined,
          // 73-07 SC1 correctness fix: restore this depth's OWN published
          // envelope (captured at push time in navigateToSubfolder), not the
          // seedActiveSharedFolder default placeholder -- write ops trust
          // this directly (see NavStackEntry.publishedNode doc).
          publishedNode: target.publishedNode,
          sequenceNumber: target.sequenceNumber ?? 0n,
          children: target.children,
          ownerPublicKey: parsePublicKey(shareEntry.share.sharerPublicKey),
          recipientPublicKey: vaultKeypair.publicKey,
        });
      } catch (err) {
        logger.error('[SharedNav] Failed to re-seed after breadcrumb restore:', err);
      }
    },
    [
      p.folderKey,
      p.currentShareId,
      p.sharedItems,
      p.seedActiveSharedFolder,
      p.zeroIpnsKey,
      p.zeroWriteKey,
    ]
  );

  /**
   * Navigate up one level.
   *
   * Restores the parent NavStackEntry captured on descent -- no network call
   * needed. Falls through to navigateToRoot when the stack is empty (root level).
   */
  const navigateUp = useCallback(async () => {
    if (p.navStackRef.current.length === 0) {
      if (p.currentView === 'folder' || p.currentView === 'file') {
        navigateToRoot();
      }
      return;
    }
    await restoreToBreadcrumbIndex(p.navStackRef.current.length - 1);
  }, [p.currentView, navigateToRoot, restoreToBreadcrumbIndex]);

  /**
   * Navigate directly to a breadcrumb level.
   *
   * Delegates to `restoreToBreadcrumbIndex` (bounds-checked there).
   */
  const navigateToBreadcrumb = useCallback(
    async (crumbIndex: number) => {
      await restoreToBreadcrumbIndex(crumbIndex);
    },
    [restoreToBreadcrumbIndex]
  );

  /**
   * Download a shared file via `client.downloadSharedFile` -- the full
   * grant->leaf read-chain walk, IPFS fetch, and decrypt all happen inside
   * the SDK (D-07); this handler only computes the `path` (every ipnsName
   * strictly between root and the leaf, inclusive of the leaf; empty when
   * the share root IS the file) and triggers the browser download.
   */
  const downloadSharedFile = useCallback(
    async (item: SealedChildRef) => {
      const currentShareId = p.currentShareId;
      if (!currentShareId) {
        p.setError('No active share');
        return;
      }
      const shareEntry = p.sharedItems.find((s) => s.share.shareId === currentShareId);
      if (!shareEntry) {
        p.setError('Shared item not found');
        return;
      }
      const share = shareEntry.share;
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) {
        p.setError('Not authenticated');
        return;
      }
      const vaultKeypair = auth.vaultKeypair;

      p.setIsLoading(true);
      p.setError(null);

      try {
        // Full folder chain from the share root (navStack[0]) down to the
        // current folder (p.ipnsName). The SDK receives the root separately
        // via shareRootIpnsName, so drop it with slice(1); the remaining hops plus
        // the leaf form the path. At the share root itself, navStack is empty
        // and p.ipnsName IS the root -- slice(1) then correctly drops it, so
        // the root is never double-counted.
        const folderChain = [
          ...p.navStackRef.current.map((entry) => entry.ipnsName),
          ...(p.ipnsName ? [p.ipnsName] : []),
        ];
        const path = p.currentView === 'file' ? [] : [...folderChain.slice(1), item.ipnsName];

        const result = await getSdkClient().downloadSharedFile({
          encryptedReadKey: share.encryptedReadKey,
          recipientPrivateKey: vaultKeypair.privateKey,
          shareRootIpnsName: share.ipnsName,
          rootExpectedGeneration: share.rootGeneration ?? 0,
          path,
        });

        if (result.status === 'revoked') {
          p.setError('File is no longer available (revoked)');
          return;
        }
        if (result.status === 'behind-retry') {
          p.setError('This share was updated -- please reopen it and try again');
          return;
        }

        triggerBrowserDownload(result.plaintext, item.name, result.mimeType);
      } catch (err) {
        logger.error('[SharedNav] Failed to download shared file:', err);
        p.setError('Failed to download file');
      } finally {
        p.setIsLoading(false);
      }
    },
    [p.currentShareId, p.sharedItems, p.currentView, p.ipnsName]
  );

  /**
   * Load a DIRECT single-file share's content (68.1-32, WEB-03 writable-shares
   * 10.3). Mirrors `downloadSharedFile`'s `client.downloadSharedFile` read
   * core but with `path: []` (the share root IS the file — no intermediate
   * hops) and returns the decrypted plaintext instead of triggering a browser
   * download, so `TextEditorDialog` can load it into the textarea. Does NOT
   * touch `downloadSharedFile` itself — the shared-FOLDER download path stays
   * byte-for-byte unchanged.
   */
  const loadSharedFileContent = useCallback(
    async (_item: SealedChildRef): Promise<Uint8Array> => {
      const currentShareId = p.currentShareId;
      if (!currentShareId) {
        throw new Error('No active share');
      }
      const shareEntry = p.sharedItems.find((s) => s.share.shareId === currentShareId);
      if (!shareEntry) {
        throw new Error('Shared item not found');
      }
      const share = shareEntry.share;
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) {
        throw new Error('Not authenticated');
      }
      const vaultKeypair = auth.vaultKeypair;

      const result = await getSdkClient().downloadSharedFile({
        encryptedReadKey: share.encryptedReadKey,
        recipientPrivateKey: vaultKeypair.privateKey,
        shareRootIpnsName: share.ipnsName,
        rootExpectedGeneration: share.rootGeneration ?? 0,
        path: [],
      });

      if (result.status === 'revoked') {
        throw new Error('File is no longer available (revoked)');
      }
      if (result.status === 'behind-retry') {
        throw new Error('This share was updated -- please reopen it and try again');
      }

      return result.plaintext;
    },
    [p.currentShareId, p.sharedItems]
  );

  /**
   * Save a DIRECT single-file share's edited content (68.1-32, WEB-03
   * writable-shares 10.3/10.4). Delegates to
   * `CipherBoxClient.updateSharedSingleFile`, which recovers the file's
   * read/write/ipnsPrivateKey directly from the grant's encrypted keys (no parent
   * folder write chain — the share root IS the file) and republishes to the
   * file's OWN IPNS at seq+1.
   */
  const saveSharedSingleFile = useCallback(
    async (_item: SealedChildRef, newContent: Uint8Array): Promise<void> => {
      const currentShareId = p.currentShareId;
      if (!currentShareId) {
        throw new Error('No active share');
      }
      const shareEntry = p.sharedItems.find((s) => s.share.shareId === currentShareId);
      if (!shareEntry) {
        throw new Error('Shared item not found');
      }
      const share = shareEntry.share;
      if (!share.encryptedWriteKey) {
        throw new Error('No write access');
      }
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) {
        throw new Error('Not authenticated');
      }
      const vaultKeypair = auth.vaultKeypair;

      // D-09: vaultKeypair.privateKey is caller-owned — never cloned or zeroed
      // here (matches moveItemHandler's identical treatment).
      await getSdkClient().updateSharedSingleFile({
        shareId: share.shareId,
        encryptedReadKey: share.encryptedReadKey,
        encryptedWriteKey: share.encryptedWriteKey,
        fileIpnsName: share.ipnsName,
        ownerPublicKey: parsePublicKey(share.sharerPublicKey),
        recipientPrivateKey: vaultKeypair.privateKey,
        recipientPublicKey: vaultKeypair.publicKey,
        rootExpectedGeneration: share.rootGeneration ?? 0,
        newContent,
      });
    },
    [p.currentShareId, p.sharedItems]
  );

  /**
   * Re-derive and re-seed the CURRENT depth's writeKey (73-07 Task 1, supplier
   * for plan 73-08's SC4 `refreshWriteAccess`).
   *
   * At the share ROOT, the writeKey source is `resolveSharedRootWriteKey`
   * over the grant's `encryptedWriteKey` -- this never depends on transient
   * per-depth SDK state, so it is always cleanly re-derivable here.
   *
   * At a DEEPER depth, `resolveSharedSubfolderWriteKey` requires the PARENT
   * depth to be the one currently seeded into the SDK's `sharedFolderTree`
   * (it reads `sharedFolderTree.get(shareId)`) -- but the depth seeded at
   * this call site is the CURRENT (child) depth, not its parent, so a clean
   * re-derivation is not reproducible from here. Falls back to re-seeding
   * from the retained `currentWriteKeyRef` (this depth's last-known-good
   * writeKey) instead of re-walking the write-chain from an unavailable
   * parent context.
   */
  const refreshCurrentDepthWriteKey = useCallback(async () => {
    const currentShareId = p.currentShareId;
    const currentIpnsName = p.ipnsName;
    const currentFolderKey = p.folderKey;
    if (!currentShareId || !currentIpnsName || !currentFolderKey) return;
    const shareEntry = p.sharedItems.find((s) => s.share.shareId === currentShareId);
    if (!shareEntry) return;
    const auth = useAuthStore.getState();
    if (!auth.vaultKeypair) return;
    const vaultKeypair = auth.vaultKeypair;

    const isRootDepth = currentIpnsName === shareEntry.share.ipnsName;
    let refreshedWriteKey: Uint8Array | null = null;

    if (isRootDepth) {
      let freshWriteKey: Uint8Array | null = null;
      try {
        freshWriteKey = await resolveSharedRootWriteKey(
          shareEntry.share.encryptedWriteKey,
          vaultKeypair.privateKey
        );
        refreshedWriteKey = freshWriteKey ? new Uint8Array(freshWriteKey) : null;
      } catch (err) {
        logger.error('[SharedNav] Failed to refresh root write key:', err);
      } finally {
        // D-09: this call's own derived buffer is the terminal owner once
        // cloned into refreshedWriteKey above.
        freshWriteKey?.fill(0);
      }
    } else {
      // See doc comment above: a deeper re-derivation needs the PARENT depth
      // seeded, not reproducible here -- fall back to the retained buffer.
      // Cloned (not read live) so the subsequent zeroWriteKey() below cannot
      // zero this snapshot out from under itself (same underlying buffer).
      refreshedWriteKey = p.currentWriteKeyRef.current
        ? new Uint8Array(p.currentWriteKeyRef.current)
        : null;
    }

    p.zeroWriteKey();
    p.currentWriteKeyRef.current = refreshedWriteKey;
    p.seedActiveSharedFolder({
      shareId: currentShareId,
      ipnsName: currentIpnsName,
      folderKey: currentFolderKey,
      ipnsPrivateKey: p.ipnsPrivateKeyRef.current ?? new Uint8Array(32),
      writeKey: refreshedWriteKey ?? undefined,
      sequenceNumber: p.currentSequenceNumber ?? 0n,
      children: p.folderChildren,
      ownerPublicKey: parsePublicKey(shareEntry.share.sharerPublicKey),
      recipientPublicKey: vaultKeypair.publicKey,
    });
  }, [
    p.currentShareId,
    p.ipnsName,
    p.folderKey,
    p.sharedItems,
    p.currentSequenceNumber,
    p.folderChildren,
    p.seedActiveSharedFolder,
    p.zeroWriteKey,
  ]);

  /**
   * Hide a shared item from the user's view.
   */
  const hideSharedItem = useCallback(
    async (shareId: string) => {
      try {
        await hideShare(shareId);
        useShareStore.getState().removeReceivedShare(shareId);
        p.setSharedItems((prev) => prev.filter((s) => s.share.shareId !== shareId));
      } catch (err) {
        logger.error('[SharedNav] Failed to hide share:', err);
        p.setError('Failed to hide shared item');
      }
    },
    [p.setSharedItems, p.setError]
  );

  return {
    navigateToShare,
    navigateToSubfolder,
    navigateUp,
    navigateToRoot,
    navigateToBreadcrumb,
    downloadSharedFile,
    loadSharedFileContent,
    saveSharedSingleFile,
    hideSharedItem,
    refreshCurrentDepthWriteKey,
  };
}
