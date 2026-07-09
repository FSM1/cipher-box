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
 */

import { useCallback, type MutableRefObject } from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import { ShareKeyCache } from '@cipherbox/sdk';
import { unwrapKey, hexToBytes } from '@cipherbox/crypto';
import { useShareStore } from '../stores/share.store';
import { useAuthStore } from '../stores/auth.store';
import { hideShare } from '../services/share.service';
import { triggerBrowserDownload } from '../services/download.service';
import { getSdkClient } from '../lib/sdk-provider';
import { logger } from '../lib/logger';
import { parsePublicKey, type SeedSharedFolderArgs } from './shared-folder-projection';
import type { SharedListItem, SharedBreadcrumb } from './useSharedNavigation';

type NavStackEntry = {
  folderId: string;
  folderName: string;
  children: SealedChildRef[];
  folderKey: Uint8Array;
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
  navStackRef: MutableRefObject<NavStackEntry[]>;
  shareKeysCacheRef: MutableRefObject<ShareKeyCache>;
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
  getShareKeys: (
    shareId: string
  ) => Promise<Array<{ keyType: string; itemId: string; encryptedKey: string }>>;
  /**
   * Seed (or re-seed) the SDK's sharedFolderTree for the active depth.
   */
  seedActiveSharedFolder: (args: Omit<SeedSharedFolderArgs, 'addShareKeysFn'>) => void;
};

/**
 * Resolve a folder's IPNS signing key for write shares.
 *
 * Write-share IPNS keys are still delivered via the legacy per-share key
 * fan-out (`getShareKeys`, keyType `folder-ipns`, itemId = folder ipnsName) --
 * unchanged by the Node-v3 read-chain migration (mirrors the identical
 * `writableSet` check in `CipherBoxClient.enumerateSharedSubtree`). Full
 * write-body (NodeWriteBody) key delivery through the grant chain is Phase-68
 * follow-on wiring; until then this is best-effort (T-68.1-05-02 zero-key
 * placeholder fallback, matching `shared-folder-projection.ts`'s existing
 * `writeKey ?? new Uint8Array(32)` convention -- write mutations remain
 * gated at the UI layer by `permission === 'write'`).
 */
async function resolveFolderIpnsPrivateKey(
  shareId: string,
  folderIpnsName: string,
  permission: 'read' | 'write',
  vaultPrivateKey: Uint8Array,
  getShareKeys: SharedNavigationActionsParams['getShareKeys']
): Promise<Uint8Array> {
  if (permission !== 'write') return new Uint8Array(32);
  try {
    const keys = await getShareKeys(shareId);
    const entry = keys.find((k) => k.keyType === 'folder-ipns' && k.itemId === folderIpnsName);
    if (!entry) return new Uint8Array(32);
    return await unwrapKey(hexToBytes(entry.encryptedKey), vaultPrivateKey);
  } catch (err) {
    logger.error('[SharedNav] Failed to resolve folder IPNS key:', err);
    return new Uint8Array(32);
  }
}

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

        const ipnsPrivateKey = await resolveFolderIpnsPrivateKey(
          shareId,
          share.ipnsName,
          share.permission,
          vaultKeypair.privateKey,
          p.getShareKeys
        );

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
          // is the terminal owner and must be zeroed here.
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
        // this only fires if something throws in between (e.g.
        // resolveFolderIpnsPrivateKey), preventing a leak.
        if (!committed && shareRootReadKey) shareRootReadKey.fill(0);
        p.setIsLoading(false);
      }
    },
    [p.sharedItems, p.getShareKeys, p.seedActiveSharedFolder, p.zeroIpnsKey]
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
          const ipnsPrivateKey = await resolveFolderIpnsPrivateKey(
            currentShareId,
            childRef.ipnsName,
            p.permission ?? 'read',
            vaultKeypair.privateKey,
            p.getShareKeys
          );

          // Push the CURRENT (pre-descent) level so navigateUp / navigateToBreadcrumb
          // can restore it without a network round-trip.
          p.navStackRef.current = [
            ...p.navStackRef.current,
            {
              folderId: currentIpnsName,
              folderName: p.breadcrumbs[p.breadcrumbs.length - 1]?.name ?? '',
              children: p.folderChildren,
              folderKey: currentFolderKey,
              ipnsName: currentIpnsName,
              sequenceNumber: p.currentSequenceNumber,
            },
          ];

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
            // navigateToShare's shareRootWriteKey finally).
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
      p.getShareKeys,
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
    }
    p.zeroIpnsKey();
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
  }, [p.folderKey, p.zeroIpnsKey, p.clearPolling]);

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

    const currentShareId = p.currentShareId;
    const stack = p.navStackRef.current;
    const parent = stack[stack.length - 1];

    // Discard the level being left (its folderKey is not referenced anywhere else).
    if (p.folderKey) p.folderKey.fill(0);
    p.navStackRef.current = stack.slice(0, -1);

    p.setFolderChildren(parent.children);
    p.setFolderKey(parent.folderKey);
    p.setIpnsName(parent.ipnsName);
    p.setCurrentSequenceNumber(parent.sequenceNumber);
    p.setBreadcrumbs((prev) => prev.slice(0, -1));

    const auth = useAuthStore.getState();
    if (!currentShareId || !auth.vaultKeypair) return;
    const vaultKeypair = auth.vaultKeypair;

    try {
      const shareEntry = p.sharedItems.find((s) => s.share.shareId === currentShareId);
      if (!shareEntry) return;
      const ipnsPrivateKey = await resolveFolderIpnsPrivateKey(
        currentShareId,
        parent.ipnsName,
        p.permission ?? 'read',
        vaultKeypair.privateKey,
        p.getShareKeys
      );
      p.zeroIpnsKey();
      p.ipnsPrivateKeyRef.current = ipnsPrivateKey;

      // T-68.1-20-01: re-derive the shared-root writeKey when this navigate-up
      // restores the share ROOT depth (the only depth a encryptedWriteKey
      // grant covers) -- a deeper subfolder restore keeps the zero-buffer
      // writeKey default untouched (see resolveSharedRootWriteKey doc).
      const isRootDepth = parent.ipnsName === shareEntry.share.ipnsName;
      const rootWriteKey = isRootDepth
        ? await resolveSharedRootWriteKey(
            shareEntry.share.encryptedWriteKey,
            vaultKeypair.privateKey
          )
        : null;
      try {
        p.seedActiveSharedFolder({
          shareId: currentShareId,
          ipnsName: parent.ipnsName,
          folderKey: parent.folderKey,
          ipnsPrivateKey,
          writeKey: rootWriteKey ?? undefined,
          sequenceNumber: parent.sequenceNumber ?? 0n,
          children: parent.children,
          ownerPublicKey: parsePublicKey(shareEntry.share.sharerPublicKey),
          recipientPublicKey: vaultKeypair.publicKey,
        });
      } finally {
        rootWriteKey?.fill(0);
      }
    } catch (err) {
      logger.error('[SharedNav] Failed to re-seed after navigate-up:', err);
    }
  }, [
    p.currentView,
    p.folderKey,
    p.currentShareId,
    p.permission,
    p.sharedItems,
    p.getShareKeys,
    p.seedActiveSharedFolder,
    p.zeroIpnsKey,
    navigateToRoot,
  ]);

  /**
   * Navigate directly to a breadcrumb level.
   *
   * Truncates the nav stack to `crumbIndex`, restoring that level's state and
   * zeroing the folderKeys of every discarded deeper level (including the
   * current live level).
   */
  const navigateToBreadcrumb = useCallback(
    async (crumbIndex: number) => {
      const stack = p.navStackRef.current;
      if (crumbIndex < 0 || crumbIndex >= stack.length) return;
      const target = stack[crumbIndex];
      const currentShareId = p.currentShareId;

      if (p.folderKey) p.folderKey.fill(0);
      for (let i = crumbIndex + 1; i < stack.length; i++) {
        stack[i].folderKey.fill(0);
      }
      p.navStackRef.current = stack.slice(0, crumbIndex);

      p.setFolderChildren(target.children);
      p.setFolderKey(target.folderKey);
      p.setIpnsName(target.ipnsName);
      p.setCurrentSequenceNumber(target.sequenceNumber);
      p.setBreadcrumbs((prev) => prev.slice(0, crumbIndex + 1));

      const auth = useAuthStore.getState();
      if (!currentShareId || !auth.vaultKeypair) return;
      const vaultKeypair = auth.vaultKeypair;

      try {
        const shareEntry = p.sharedItems.find((s) => s.share.shareId === currentShareId);
        if (!shareEntry) return;
        const ipnsPrivateKey = await resolveFolderIpnsPrivateKey(
          currentShareId,
          target.ipnsName,
          p.permission ?? 'read',
          vaultKeypair.privateKey,
          p.getShareKeys
        );
        p.zeroIpnsKey();
        p.ipnsPrivateKeyRef.current = ipnsPrivateKey;

        // T-68.1-20-01: same root-depth-only writeKey re-derivation as
        // navigateUp -- see resolveSharedRootWriteKey doc.
        const isRootDepth = target.ipnsName === shareEntry.share.ipnsName;
        const rootWriteKey = isRootDepth
          ? await resolveSharedRootWriteKey(
              shareEntry.share.encryptedWriteKey,
              vaultKeypair.privateKey
            )
          : null;
        try {
          p.seedActiveSharedFolder({
            shareId: currentShareId,
            ipnsName: target.ipnsName,
            folderKey: target.folderKey,
            ipnsPrivateKey,
            writeKey: rootWriteKey ?? undefined,
            sequenceNumber: target.sequenceNumber ?? 0n,
            children: target.children,
            ownerPublicKey: parsePublicKey(shareEntry.share.sharerPublicKey),
            recipientPublicKey: vaultKeypair.publicKey,
          });
        } finally {
          rootWriteKey?.fill(0);
        }
      } catch (err) {
        logger.error('[SharedNav] Failed to re-seed after breadcrumb navigation:', err);
      }
    },
    [
      p.folderKey,
      p.currentShareId,
      p.permission,
      p.sharedItems,
      p.getShareKeys,
      p.seedActiveSharedFolder,
      p.zeroIpnsKey,
    ]
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
  };
}
