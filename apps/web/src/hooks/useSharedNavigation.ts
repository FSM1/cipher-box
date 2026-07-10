/**
 * useSharedNavigation -- Orchestrator hook for browsing shared content.
 *
 * Owns state declarations, share loading, polling, cleanup, and delegates to:
 * - useSharedNavigationActions: navigation callbacks (navigate, download, hide)
 * - useSharedWriteOps: write operation handlers (upload, mkdir, rename, delete)
 *
 * Security: All keys are ECIES-wrapped for the current user.
 * The server never sees plaintext keys.
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import { type SealedChildRef, type PublishedNode } from '@cipherbox/core';
import { type ResolvedChild } from '@cipherbox/sdk';
import { useShareStore, type ReceivedShare } from '../stores/share.store';
import { fetchReceivedShares, decryptItemName } from '../services/share.service';
import { useAuthStore } from '../stores/auth.store';
import { getSdkClient, hasSdkClient } from '../lib/sdk-provider';
import { logger } from '../lib/logger';
import { useSharedNavigationActions } from './useSharedNavigationActions';
import { useSharedWriteOps } from './useSharedWriteOps';
import {
  seedSharedFolder,
  subscribeSharedFolderProjection,
  type SeedSharedFolderArgs,
} from './shared-folder-projection';

/**
 * Breadcrumb entry for shared navigation.
 */
export type SharedBreadcrumb = {
  id: string;
  name: string;
};

/**
 * A shared item displayed in the top-level shared list.
 */
export type SharedListItem = {
  share: ReceivedShare;
  /** Resolved folder children (for folders), or null (for files / unresolved) */
  children: SealedChildRef[] | null;
  /** Folder key for this shared item (decrypted from share record) */
  folderKey: Uint8Array | null;
};

type SharedView = 'list' | 'folder' | 'file';

type UseSharedNavigationReturn = {
  currentView: SharedView;
  currentShareId: string | null;
  sharedItems: SharedListItem[];
  folderChildren: SealedChildRef[];
  /**
   * Resolved display projection of `folderChildren` for the CURRENT depth
   * (68.2-08, SDK-READ-02) -- `kind`/`size`/`modifiedAt` pre-resolved via
   * `client.listSharedFolder`. `folderChildren` itself stays `SealedChildRef[]`
   * (identity/crypto carrier for write-op calls, which need `readKeySealed`);
   * this is the parallel display source consumers should render from.
   */
  resolvedChildren: ResolvedChild[];
  folderKey: Uint8Array | null;
  breadcrumbs: SharedBreadcrumb[];
  isLoading: boolean;
  error: string | null;
  /** Current share's permission (null when at top-level list) */
  permission: 'read' | 'write' | null;
  /** Unwrapped IPNS private key for write shares (null for read-only) */
  ipnsPrivateKey: Uint8Array | null;
  /** Current folder's IPNS name (needed for write operations) */
  ipnsName: string | null;
  /** Latest known sequence number for conflict detection */
  currentSequenceNumber: bigint | null;
  navigateToShare: (shareId: string) => Promise<void>;
  navigateToSubfolder: (folderId: string, folderName: string) => Promise<void>;
  navigateUp: () => void;
  navigateToRoot: () => void;
  navigateToBreadcrumb: (crumbIndex: number) => void;
  /** @stub phase 63 — file download requires Node read-chain navigation */
  downloadSharedFile: (item: SealedChildRef) => Promise<void>;
  /**
   * Load a DIRECT single-file share's content via the node/v3 read chain
   * (68.1-32, WEB-03 writable-shares 10.3). Used by the text editor when the
   * share root IS the file (`currentView === 'file'`) — no `folderKey`/
   * `readKeySealed` dependency.
   */
  loadSharedFileContent: (item: SealedChildRef) => Promise<Uint8Array>;
  /**
   * Save a DIRECT single-file share's edited content (68.1-32, WEB-03
   * writable-shares 10.3/10.4) — write-grant recipients only.
   */
  saveSharedSingleFile: (item: SealedChildRef, newContent: Uint8Array) => Promise<void>;
  hideSharedItem: (shareId: string) => Promise<void>;
  /** Upload a file to the currently-viewed write-shared folder */
  uploadFile: (file: File) => Promise<void>;
  /** Create a subfolder in the currently-viewed write-shared folder */
  createFolder: (name: string) => Promise<void>;
  /** Rename an item in the currently-viewed write-shared folder */
  renameItem: (item: SealedChildRef, newName: string) => Promise<void>;
  /** Delete an item from the currently-viewed write-shared folder */
  deleteItem: (item: SealedChildRef) => Promise<void>;
  /** @stub phase 65 — shared file update requires Node read-chain */
  updateSharedFile: (item: SealedChildRef, newContent: Uint8Array) => Promise<void>;
  /** Move an item to a destination subfolder within the same share */
  moveItem: (item: SealedChildRef, destFolderId: string, destIpnsName: string) => Promise<void>;
  /** Move multiple items to a destination subfolder (web-layer loop, no SDK batch op) */
  batchMoveItems: (
    items: SealedChildRef[],
    destFolderId: string,
    destIpnsName: string,
    clearSelection: () => void
  ) => Promise<void>;
  /**
   * Re-derive and re-seed the CURRENT depth's writeKey (73-07 Task 1, supplier
   * for plan 73-08's SC4 `refreshWriteAccess`).
   */
  refreshCurrentDepthWriteKey: () => Promise<void>;
};

/**
 * Hook for browsing shared content.
 *
 * Manages the "Shared with me" browsing experience.
 * Top-level view shows received shares as a flat list.
 * Clicking a shared folder navigates into it using re-wrapped keys.
 *
 * For write shares, also provides write operation handlers and 30s polling.
 */
export function useSharedNavigation(): UseSharedNavigationReturn {
  // ---------------------------------------------------------------------------
  // State declarations
  // ---------------------------------------------------------------------------
  const [currentView, setCurrentView] = useState<SharedView>('list');
  const [currentShareId, setCurrentShareId] = useState<string | null>(null);
  const [sharedItems, setSharedItems] = useState<SharedListItem[]>([]);
  const [folderChildren, setFolderChildren] = useState<SealedChildRef[]>([]);
  const [resolvedChildren, setResolvedChildren] = useState<ResolvedChild[]>([]);
  const [folderKey, setFolderKey] = useState<Uint8Array | null>(null);
  const [breadcrumbs, setBreadcrumbs] = useState<SharedBreadcrumb[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [permission, setPermission] = useState<'read' | 'write' | null>(null);
  const [ipnsName, setIpnsName] = useState<string | null>(null);
  const [currentSequenceNumber, setCurrentSequenceNumber] = useState<bigint | null>(null);

  // Refs for values consumed in retry closures (C-01: avoids stale closure captures)
  const folderChildrenRef = useRef<SealedChildRef[]>([]);
  const sequenceNumberRef = useRef<bigint | null>(null);

  // IPNS private key stored in ref to avoid re-renders; zeroed on cleanup
  const ipnsPrivateKeyRef = useRef<Uint8Array | null>(null);

  // Active-depth writeKey (73-07, SC1) -- mirrors ipnsPrivateKeyRef; owned by
  // either this ref (active depth) or a NavStackEntry.writeKey (suspended
  // depth), never both at once. Zeroed on cleanup.
  const currentWriteKeyRef = useRef<Uint8Array | null>(null);

  // Navigation stack for folder browsing within a share
  const navStackRef = useRef<
    Array<{
      folderId: string;
      folderName: string;
      children: SealedChildRef[];
      folderKey: Uint8Array;
      writeKey: Uint8Array | null;
      publishedNode: PublishedNode;
      ipnsName: string;
      sequenceNumber: bigint | null;
    }>
  >([]);

  // Polling interval ref for 30s sync
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Active shareId mirror — read at event time by the sharedFolder:updated
  // projection so the (stable) subscription stays correct as the share changes.
  const currentShareIdRef = useRef<string | null>(null);
  currentShareIdRef.current = currentShareId;

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  const zeroIpnsKey = useCallback(() => {
    if (ipnsPrivateKeyRef.current) {
      ipnsPrivateKeyRef.current.fill(0);
      ipnsPrivateKeyRef.current = null;
    }
  }, []);

  const zeroWriteKey = useCallback(() => {
    if (currentWriteKeyRef.current) {
      currentWriteKeyRef.current.fill(0);
      currentWriteKeyRef.current = null;
    }
  }, []);

  const clearPolling = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
  }, []);

  const handleRevocation = useCallback(
    (showError?: boolean) => {
      zeroIpnsKey();
      setPermission('read');
      if (showError) {
        setError('Write access revoked. Folder is now read-only.');
      }
    },
    [zeroIpnsKey]
  );

  /**
   * Seed (or re-seed) the SDK's sharedFolderTree for the active shared-folder
   * depth. Invoked by the navigation actions on share-enter / subfolder-enter /
   * up / breadcrumb — the only places the active folder context changes.
   *
   * The SDK becomes the single source of truth for shared write state (REQ-3);
   * `seedSharedFolder` clones key buffers internally so the caller's keys stay
   * owned by the web hook (zeroed on cleanup).
   */
  const seedActiveSharedFolder = useCallback(
    (args: Omit<SeedSharedFolderArgs, 'addShareKeysFn'>) => {
      if (!hasSdkClient()) return;
      seedSharedFolder(getSdkClient(), {
        ...args,
        // No-op: the web `addShareKeys` fan-out this called into is deleted
        // (SC#2 / D-12) — it never worked (always threw the Phase-68-deferred
        // stub), so this preserves the same effective behavior without the
        // dead per-mutation key-wrap loop.
        addShareKeysFn: async () => {},
      });
    },
    []
  );

  // ---------------------------------------------------------------------------
  // Share loading effect
  // ---------------------------------------------------------------------------

  useEffect(() => {
    let cancelled = false;

    async function loadShares() {
      setIsLoading(true);
      setError(null);

      try {
        const pageSize = 100;
        let offset = 0;
        const shares: ReceivedShare[] = [];

        while (true) {
          const page = await fetchReceivedShares(pageSize, offset);
          if (cancelled) return;
          shares.push(...page.shares);
          offset += page.shares.length;
          if (offset >= page.total || page.shares.length === 0) break;
        }

        // Decrypt itemNameEncrypted into the plaintext display projection
        // (REQ-4 recipient-side decrypt — the v2.0 refactor dropped this
        // wiring, leaving every received share rendered with an empty name;
        // restored in 68.1-22). Per-share failures leave itemName as-is.
        const vaultPrivateKey = useAuthStore.getState().vaultKeypair?.privateKey;
        if (vaultPrivateKey) {
          await Promise.all(
            shares.map(async (share) => {
              try {
                share.itemName = await decryptItemName(share, vaultPrivateKey);
              } catch {
                // Ciphertext not decryptable with this key — keep the fallback.
              }
            })
          );
          if (cancelled) return;
        }

        useShareStore.getState().setReceivedShares(shares);

        const items: SharedListItem[] = shares.map((share) => ({
          share,
          children: null,
          folderKey: null,
        }));

        setSharedItems(items);
      } catch (err) {
        if (cancelled) return;
        logger.error('[SharedNav] Failed to load shared items:', err);
        setError('Failed to load shared items');
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    }

    loadShares();
    return () => {
      cancelled = true;
      setFolderKey((prev) => {
        if (prev) prev.fill(0);
        return null;
      });
      for (const entry of navStackRef.current) {
        entry.folderKey.fill(0);
        entry.writeKey?.fill(0);
      }
      navStackRef.current = [];
      zeroIpnsKey();
      zeroWriteKey();
      clearPolling();
    };
  }, [zeroIpnsKey, zeroWriteKey, clearPolling]);

  // ---------------------------------------------------------------------------
  // sharedFolder:updated projection (REQ-3)
  //
  // folderChildrenRef/sequenceNumberRef + their setters are written ONLY here
  // post-mutation: the write hook reads nothing back. The subscription filters
  // on the active shareId (read via ref) so it stays correct across navigation
  // and ignores events for other shares (no cross-share state bleed, T-48-10).
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (!hasSdkClient()) return;
    const unsubscribe = subscribeSharedFolderProjection(
      getSdkClient(),
      () => currentShareIdRef.current,
      (children, sequenceNumber) => {
        folderChildrenRef.current = children;
        sequenceNumberRef.current = sequenceNumber;
        setFolderChildren(children);
        setCurrentSequenceNumber(sequenceNumber);
      }
    );
    return () => {
      unsubscribe();
      // Zero the SDK's cloned shared-folder key material on unmount — the web
      // never otherwise unloads it (unloadSharedFolder deletes the entry, which
      // zeroes folderKey + ipnsPrivateKey). Guarded: no-op when no active share.
      const activeShareId = currentShareIdRef.current;
      if (activeShareId && hasSdkClient()) {
        getSdkClient().unloadSharedFolder(activeShareId);
      }
    };
  }, []);

  // ---------------------------------------------------------------------------
  // Resolved display projection (68.2-08, D-02) -- `client.listSharedFolder`
  // resolves the CURRENT depth's children (already seeded into
  // `sharedFolderTree` by every nav action / the projection above) into
  // `ResolvedChild[]` for display. Re-runs whenever the current depth's raw
  // children or sequence changes (navigation, `sharedFolder:updated`).
  // Cached in-SDK by ipnsName+sequenceNumber (Plan 02), so repeat calls at an
  // unchanged depth are cheap.
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (currentView !== 'folder' || !currentShareId || !hasSdkClient()) {
      setResolvedChildren([]);
      return;
    }
    let cancelled = false;
    getSdkClient()
      .listSharedFolder(currentShareId, [])
      .then((resolved) => {
        if (!cancelled) setResolvedChildren(resolved);
      })
      .catch((err) => {
        if (!cancelled) {
          logger.error('[SharedNav] Failed to resolve shared listing for display:', err);
          setResolvedChildren([]);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [currentView, currentShareId, folderChildren, currentSequenceNumber]);

  // ---------------------------------------------------------------------------
  // Delegate to sub-hooks
  // ---------------------------------------------------------------------------

  const navActions = useSharedNavigationActions({
    sharedItems,
    folderChildren,
    folderKey,
    breadcrumbs,
    currentShareId,
    permission,
    ipnsName,
    currentSequenceNumber,
    currentView,
    folderChildrenRef,
    sequenceNumberRef,
    ipnsPrivateKeyRef,
    currentWriteKeyRef,
    navStackRef,
    setCurrentView,
    setCurrentShareId,
    setFolderChildren,
    setFolderKey,
    setBreadcrumbs,
    setPermission,
    setIpnsName,
    setCurrentSequenceNumber,
    setIsLoading,
    setError,
    setSharedItems,
    clearPolling,
    zeroIpnsKey,
    zeroWriteKey,
    seedActiveSharedFolder,
  });

  const writeOps = useSharedWriteOps({
    currentShareId,
    sharedItems,
    setIsLoading,
    setError,
    handleRevocation,
  });

  // ---------------------------------------------------------------------------
  // 30s sync polling for write shares
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (currentView !== 'folder' || permission !== 'write' || !ipnsName || !folderKey) {
      clearPolling();
      return;
    }

    pollIntervalRef.current = setInterval(async () => {
      try {
        const freshShares = await fetchReceivedShares(100, 0);
        const currentShare = freshShares.shares.find((s) => s.shareId === currentShareId);

        if (!currentShare || currentShare.permission !== 'write') {
          useShareStore.getState().setReceivedShares(freshShares.shares);
          handleRevocation(false);
          clearPolling();
          return;
        }

        // Pull remote shared changes through the SDK. refreshSharedFolder
        // re-resolves the seeded depth's IPNS, applies the #489 sequence-guard,
        // and emits sharedFolder:updated — the projection subscription is the
        // sole writer of folderChildrenRef/sequenceNumberRef (write AND poll).
        if (currentShareId && hasSdkClient()) {
          await getSdkClient().refreshSharedFolder(currentShareId);
        }
      } catch {
        // Silent failure during polling
      }
    }, 30000);

    return () => {
      clearPolling();
    };
  }, [
    currentView,
    permission,
    ipnsName,
    folderKey,
    currentShareId,
    clearPolling,
    handleRevocation,
  ]);

  // ---------------------------------------------------------------------------
  // Return unified API
  // ---------------------------------------------------------------------------

  return {
    currentView,
    currentShareId,
    sharedItems,
    folderChildren,
    resolvedChildren,
    folderKey,
    breadcrumbs,
    isLoading,
    error,
    permission,
    ipnsPrivateKey: ipnsPrivateKeyRef.current,
    ipnsName,
    currentSequenceNumber,
    ...navActions,
    ...writeOps,
  };
}
