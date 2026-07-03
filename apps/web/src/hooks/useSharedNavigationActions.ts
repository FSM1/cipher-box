/**
 * useSharedNavigationActions -- Navigation action handlers for shared content.
 *
 * Wires the shared-folder read-chain (Node v3): navigateToShare / navigateToSubfolder
 * descend by unwrapping the grant's readDescriptorRef (root) or unsealing a
 * SealedChildRef.readKeySealed (subfolder hop, generation-source rule --
 * childRef.generation, the PARENT MIRROR, never the child's own envelope
 * generation, §2.6). navigateUp / navigateToBreadcrumb restore prior levels
 * from the in-memory nav stack (no network round-trip). downloadSharedFile
 * walks the full grant->leaf chain via sdk-core's navigateReadChain and
 * decrypts with the leaf's raw fileKey.
 *
 * Security (D-09): recipient vault private key is caller-owned, never zeroed
 * here. Minted intermediates (share-root/subfolder readKeys, raw fileKey) are
 * zeroed on every exit path once they are no longer the live state.
 */

import { useCallback, type MutableRefObject } from 'react';
import type { SealedChildRef, PublishedNode } from '@cipherbox/core';
import { unsealNode, unsealChildReadKey } from '@cipherbox/core';
import { ShareKeyCache } from '@cipherbox/sdk';
import {
  navigateReadChain,
  resolveIpnsRecord,
  fetchFromIpfs,
  type SdkContext,
} from '@cipherbox/sdk-core';
import { unwrapKey, hexToBytes, decryptAesGcm, decryptAesCtr } from '@cipherbox/crypto';
import { useShareStore } from '../stores/share.store';
import { useAuthStore } from '../stores/auth.store';
import { hideShare } from '../services/share.service';
import { triggerBrowserDownload } from '../services/download.service';
import { getSdkClient } from '../lib/sdk-provider';
import { logger } from '../lib/logger';
import { resolveKinds } from '../lib/kind-cache';
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

// ---------------------------------------------------------------------------
// Read-chain helpers (mirror packages/sdk-core/src/share/navigate.ts's private
// helpers -- duplicated here because folder navigation needs to stop at an
// intermediate FOLDER node, while sdk-core's navigateReadChain always requires
// the walked-to leaf to be a FILE node).
// ---------------------------------------------------------------------------

/** Decode a base64 string to raw bytes (browser atob-based). */
function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encode raw bytes to base64 (browser btoa-based).
 *
 * Bridges the web's hex-encoded `readDescriptorRef` (API DTO contract --
 * `apps/api/src/shares/shares.service.ts` stores/serializes it as hex) into
 * `navigateReadChain`'s base64 contract (sdk-core's own `issueReadGrant`
 * produces base64 -- the two encodings diverge at the API boundary).
 */
function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

/**
 * Resolve an IPNS name and return its raw PublishedNode envelope + sequence.
 * Returns null when the IPNS record is absent (revoked / not-found, fail-closed).
 */
async function fetchPublishedNode(
  ipnsName: string,
  ctx: SdkContext
): Promise<{ published: PublishedNode; sequenceNumber: bigint } | null> {
  const resolved = await resolveIpnsRecord(ipnsName, ctx);
  if (!resolved) return null;
  const raw = await fetchFromIpfs(ctx, resolved.cid);
  const published = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
  return { published, sequenceNumber: resolved.sequenceNumber };
}

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
/**
 * Unwrap a grant's `writeDescriptorRef` into the shared-root writeKey
 * (68.1-20, SHARE-WRITE-KEY recipient side).
 *
 * Only meaningful for the share ROOT: a node's writeKey under the node/v3
 * write-chain is sealed inside its PARENT's write-body (`WriteChildRef.
 * writeKeySealed`), so the descriptor-ref grant only ever carries the
 * shared item's OWN root writeKey -- there is no equivalent per-subfolder
 * descriptor to unwrap deeper in the tree (that requires a write-chain walk
 * from this root writeKey, out of this helper's scope -- see client.ts
 * `moveInSharedFolder`, 68.1-20 Task 3).
 *
 * Returns `null` for read-only grants (no `writeDescriptorRef`) so callers
 * preserve the existing zero-buffer `writeKey` seed default untouched
 * (T-68.1-20-01: a read-only grant can never recover a usable writeKey).
 */
async function resolveSharedRootWriteKey(
  writeDescriptorRef: string | null | undefined,
  vaultPrivateKey: Uint8Array
): Promise<Uint8Array | null> {
  if (!writeDescriptorRef) return null;
  return unwrapKey(hexToBytes(writeDescriptorRef), vaultPrivateKey);
}

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

export function useSharedNavigationActions(p: SharedNavigationActionsParams) {
  /**
   * Navigate into a shared folder/file from the top-level list.
   *
   * ONE ECIES unwrap of `readDescriptorRef` -> share-root readKey, resolve +
   * unseal the root Node. A `kind: 'file'` root (single-file share) switches
   * to `currentView: 'file'` instead -- `SharedFileBrowser`'s effect then
   * calls `downloadSharedFile` with a synthetic root-referencing ref.
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

      // D-09: recipient private key is caller-owned -- never zeroed by this handler.
      const wrapped = hexToBytes(share.readDescriptorRef);
      const shareRootReadKey = await unwrapKey(wrapped, vaultKeypair.privateKey);
      let committed = false;

      try {
        const ctx = getSdkClient().getContext();
        const fetched = await fetchPublishedNode(share.ipnsName, ctx);
        if (!fetched) {
          p.setError('Share is no longer available (revoked)');
          return;
        }
        const { published: rootPublished, sequenceNumber: rootSeq } = fetched;

        // T-68.1-05-03: behind-retry -- root rotated since the grant witness.
        if (share.rootGeneration !== undefined && rootPublished.generation > share.rootGeneration) {
          p.setError('This share was updated -- please reopen it');
          return;
        }

        const rootNode = await unsealNode(rootPublished, shareRootReadKey);

        p.navStackRef.current = [];
        p.setCurrentShareId(shareId);
        p.setPermission(share.permission);

        if (rootNode.kind === 'file') {
          // Single-file share: the root IS the leaf. Discard the readKey we
          // minted to determine the kind -- downloadSharedFile independently
          // re-derives the full chain via navigateReadChain (path: []).
          p.setFolderChildren([]);
          p.setFolderKey(null);
          p.setIpnsName(null);
          p.setCurrentSequenceNumber(null);
          p.setBreadcrumbs([]);
          p.setCurrentView('file');
          return;
        }

        const children = rootNode.children ?? [];
        const ipnsPrivateKey = await resolveFolderIpnsPrivateKey(
          shareId,
          share.ipnsName,
          share.permission,
          vaultKeypair.privateKey,
          p.getShareKeys
        );

        // D-02: populate the kind cache before setFolderChildren so
        // SharedFileBrowser's synchronous isFileRef guards read the resolved
        // kind on first render.
        await resolveKinds(children);

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
        // writeDescriptorRef (write grants only) -- read-only grants keep the
        // SDK's zero-buffer writeKey default (cannot unseal the write-body).
        const shareRootWriteKey = await resolveSharedRootWriteKey(
          share.writeDescriptorRef,
          vaultKeypair.privateKey
        );
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
            publishedNode: rootPublished,
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
        if (!committed) shareRootReadKey.fill(0);
        p.setIsLoading(false);
      }
    },
    [p.sharedItems, p.getShareKeys, p.seedActiveSharedFolder, p.zeroIpnsKey]
  );

  /**
   * Navigate into a subfolder within a shared folder.
   *
   * One read-chain hop: find the target's SealedChildRef in the currently
   * loaded children, unseal its readKey under the CURRENT folderKey using
   * `childRef.generation` (parent mirror -- generation-source rule, never the
   * child's own envelope generation), unseal the child Node.
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
        const ctx = getSdkClient().getContext();
        const fetched = await fetchPublishedNode(childRef.ipnsName, ctx);
        if (!fetched) {
          p.setError('Folder is no longer available (revoked)');
          return;
        }
        const { published: childPublished, sequenceNumber: childSeq } = fetched;

        const childReadKey = await unsealChildReadKey(
          childRef.readKeySealed,
          currentFolderKey,
          childPublished.id,
          childPublished.kind,
          childRef.generation // parent mirror -- NOT childPublished.generation
        );

        let committed = false;
        try {
          const childNode = await unsealNode(childPublished, childReadKey);
          const children = childNode.children ?? [];

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

          // D-02: populate the kind cache before setFolderChildren so the
          // resolved kind is present on first render of this level.
          await resolveKinds(children);

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
            { published: childPublished, readKey: childReadKey, generation: childRef.generation }
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
              publishedNode: childPublished,
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
    // D-02: parent.children were already resolved on descent, so this is a
    // memoized no-op in the common case — kept for consistency / defense in
    // depth in case the cache was cleared (e.g. logout/login) in between.
    await resolveKinds(parent.children);
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
      // restores the share ROOT depth (the only depth a writeDescriptorRef
      // grant covers) -- a deeper subfolder restore keeps the zero-buffer
      // writeKey default untouched (see resolveSharedRootWriteKey doc).
      const isRootDepth = parent.ipnsName === shareEntry.share.ipnsName;
      const rootWriteKey = isRootDepth
        ? await resolveSharedRootWriteKey(
            shareEntry.share.writeDescriptorRef,
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
      // D-02: target.children were already resolved on descent, so this is a
      // memoized no-op in the common case — kept for consistency / defense in
      // depth in case the cache was cleared (e.g. logout/login) in between.
      await resolveKinds(target.children);
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
              shareEntry.share.writeDescriptorRef,
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
   * Download a shared file using the full grant->leaf read-chain.
   *
   * Walks `navigateReadChain` from the share root to `item` (path = every
   * ipnsName strictly between root and the leaf, inclusive of the leaf;
   * empty when the share root IS the file, single-file-share case), then
   * fetches the CID and decrypts with the leaf's RAW fileKey (base64 iv).
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
        const ctx = getSdkClient().getContext();

        const path =
          p.currentView === 'file'
            ? []
            : [
                ...p.navStackRef.current.map((entry) => entry.ipnsName).slice(1),
                ...(p.ipnsName ? [p.ipnsName] : []),
                item.ipnsName,
              ];

        const result = await navigateReadChain({
          readDescriptorRef: bytesToBase64(hexToBytes(share.readDescriptorRef)),
          recipientPrivKey: vaultKeypair.privateKey,
          rootIpnsName: share.ipnsName,
          rootExpectedGeneration: share.rootGeneration ?? 0,
          path,
          ctx,
        });

        if (result.status === 'revoked') {
          p.setError('File is no longer available (revoked)');
          return;
        }
        if (result.status === 'behind-retry') {
          p.setError('This share was updated -- please reopen it and try again');
          return;
        }

        const { content } = result;
        const ciphertext = await fetchFromIpfs(ctx, content.cid);
        const iv = base64ToBytes(content.fileIv);

        try {
          const plaintext =
            content.encryptionMode === 'CTR'
              ? await decryptAesCtr(ciphertext, content.fileKey, iv)
              : await decryptAesGcm(ciphertext, content.fileKey, iv);
          triggerBrowserDownload(plaintext, item.name, content.mimeType);
        } finally {
          // T-68.1-05 mirror of T-68.1-04-01: this handler is the terminal
          // owner of the raw fileKey recovered inside NodeContent (D-09).
          content.fileKey.fill(0);
        }
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
   * 10.3). Mirrors `downloadSharedFile`'s `navigateReadChain` read core but with
   * `path: []` (the share root IS the file — no intermediate hops) and returns
   * the decrypted plaintext instead of triggering a browser download, so
   * `TextEditorDialog` can load it into the textarea. Does NOT touch
   * `downloadSharedFile` itself — the shared-FOLDER download path stays
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

      const ctx = getSdkClient().getContext();

      const result = await navigateReadChain({
        readDescriptorRef: bytesToBase64(hexToBytes(share.readDescriptorRef)),
        recipientPrivKey: vaultKeypair.privateKey,
        rootIpnsName: share.ipnsName,
        rootExpectedGeneration: share.rootGeneration ?? 0,
        path: [],
        ctx,
      });

      if (result.status === 'revoked') {
        throw new Error('File is no longer available (revoked)');
      }
      if (result.status === 'behind-retry') {
        throw new Error('This share was updated -- please reopen it and try again');
      }

      const { content } = result;
      const ciphertext = await fetchFromIpfs(ctx, content.cid);
      const iv = base64ToBytes(content.fileIv);

      try {
        return content.encryptionMode === 'CTR'
          ? await decryptAesCtr(ciphertext, content.fileKey, iv)
          : await decryptAesGcm(ciphertext, content.fileKey, iv);
      } finally {
        // Terminal owner of the raw fileKey recovered inside NodeContent (D-09),
        // mirrors downloadSharedFile's identical finally.
        content.fileKey.fill(0);
      }
    },
    [p.currentShareId, p.sharedItems]
  );

  /**
   * Save a DIRECT single-file share's edited content (68.1-32, WEB-03
   * writable-shares 10.3/10.4). Delegates to
   * `CipherBoxClient.updateSharedSingleFile`, which recovers the file's
   * read/write/ipnsPrivateKey directly from the grant descriptors (no parent
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
      if (!share.writeDescriptorRef) {
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
        readDescriptorRef: share.readDescriptorRef,
        writeDescriptorRef: share.writeDescriptorRef,
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
