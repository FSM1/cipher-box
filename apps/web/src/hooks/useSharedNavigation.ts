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
import { type FolderChild, type FilePointer } from '@cipherbox/core';
import { ShareKeyCache } from '@cipherbox/sdk';
import { useShareStore, type ReceivedShare } from '../stores/share.store';
import { fetchReceivedShares, fetchShareKeys, addShareKeys } from '../services/share.service';
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
  children: FolderChild[] | null;
  /** Folder key for this shared item (decrypted from share record) */
  folderKey: Uint8Array | null;
};

type SharedView = 'list' | 'folder' | 'file';

type UseSharedNavigationReturn = {
  currentView: SharedView;
  currentShareId: string | null;
  sharedItems: SharedListItem[];
  folderChildren: FolderChild[];
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
  downloadSharedFile: (item: FilePointer) => Promise<void>;
  hideSharedItem: (shareId: string) => Promise<void>;
  /** Upload a file to the currently-viewed write-shared folder */
  uploadFile: (file: File) => Promise<void>;
  /** Create a subfolder in the currently-viewed write-shared folder */
  createFolder: (name: string) => Promise<void>;
  /** Rename an item in the currently-viewed write-shared folder */
  renameItem: (item: FolderChild, newName: string) => Promise<void>;
  /** Delete an item from the currently-viewed write-shared folder */
  deleteItem: (item: FolderChild) => Promise<void>;
  /** Update a file's content in the currently-viewed write-shared folder */
  updateSharedFile: (item: FilePointer, newContent: Uint8Array) => Promise<void>;
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
  const [folderChildren, setFolderChildren] = useState<FolderChild[]>([]);
  const [folderKey, setFolderKey] = useState<Uint8Array | null>(null);
  const [breadcrumbs, setBreadcrumbs] = useState<SharedBreadcrumb[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [permission, setPermission] = useState<'read' | 'write' | null>(null);
  const [ipnsName, setIpnsName] = useState<string | null>(null);
  const [currentSequenceNumber, setCurrentSequenceNumber] = useState<bigint | null>(null);

  // Refs for values consumed in retry closures (C-01: avoids stale closure captures)
  const folderChildrenRef = useRef<FolderChild[]>([]);
  const sequenceNumberRef = useRef<bigint | null>(null);

  // IPNS private key stored in ref to avoid re-renders; zeroed on cleanup
  const ipnsPrivateKeyRef = useRef<Uint8Array | null>(null);

  // Navigation stack for folder browsing within a share
  const navStackRef = useRef<
    Array<{
      folderId: string;
      folderName: string;
      children: FolderChild[];
      folderKey: Uint8Array;
      ipnsName: string;
      sequenceNumber: bigint | null;
    }>
  >([]);

  // Cache share keys per shareId with TTL to avoid refetching
  const shareKeysCacheRef = useRef(new ShareKeyCache(60_000));

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

  const getShareKeys = useCallback(async (shareId: string) => {
    const cached = shareKeysCacheRef.current.get(shareId);
    if (cached) return cached;

    const keys = await fetchShareKeys(shareId);
    shareKeysCacheRef.current.set(shareId, keys);
    return keys;
  }, []);

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
        addShareKeysFn: async (sid, keys) => {
          await addShareKeys(sid, keys);
          shareKeysCacheRef.current.invalidate(sid);
        },
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
      }
      navStackRef.current = [];
      zeroIpnsKey();
      clearPolling();
      shareKeysCacheRef.current.clear();
    };
  }, [zeroIpnsKey, clearPolling]);

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
    return unsubscribe;
  }, []);

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
    navStackRef,
    shareKeysCacheRef,
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
    getShareKeys,
    seedActiveSharedFolder,
  });

  const writeOps = useSharedWriteOps({
    currentShareId,
    folderKey,
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
