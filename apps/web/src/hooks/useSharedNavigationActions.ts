/**
 * useSharedNavigationActions -- Navigation action handlers for shared content.
 *
 * @stub phase 63 — All navigation handlers require the Node read-chain.
 * The FolderMetadata/FileMetadata decryption path used FolderEntry/FilePointer
 * (retired) and decryptFolderMetadata/decryptFileMetadata (retired). The v3
 * Node codec replaces these; phase 63 will restore full navigation using
 * SealedChildRef + Node read-body unsealing.
 */

import { useCallback, type MutableRefObject } from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import { ShareKeyCache } from '@cipherbox/sdk';
import { useShareStore } from '../stores/share.store';
import { hideShare } from '../services/share.service';
import { logger } from '../lib/logger';
import type { SeedSharedFolderArgs } from './shared-folder-projection';
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

export function useSharedNavigationActions(p: SharedNavigationActionsParams) {
  /**
   * Navigate into a shared folder/file from the top-level list.
   * @stub phase 63 — requires Node read-chain (SealedChildRef unsealing)
   */
  const navigateToShare = useCallback(async (_shareId: string) => {
    throw new Error(
      'not implemented — phase 63 (shared folder navigation requires Node read-chain)'
    );
  }, []);

  /**
   * Navigate into a subfolder within a shared folder.
   * @stub phase 63 — requires Node read-chain
   */
  const navigateToSubfolder = useCallback(async (_folderId: string, _folderName: string) => {
    throw new Error(
      'not implemented — phase 63 (shared subfolder navigation requires Node read-chain)'
    );
  }, []);

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
   * @stub phase 63 — requires Node read-chain for key restoration
   */
  const navigateUp = useCallback(async () => {
    if (p.navStackRef.current.length === 0) {
      if (p.currentView === 'folder' || p.currentView === 'file') {
        navigateToRoot();
      }
      return;
    }
    throw new Error(
      'not implemented — phase 63 (shared folder navigate-up requires Node read-chain)'
    );
  }, [p.currentView, p.folderKey, navigateToRoot]);

  /**
   * Navigate directly to a breadcrumb level.
   * @stub phase 63 — requires Node read-chain
   */
  const navigateToBreadcrumb = useCallback(async (_crumbIndex: number) => {
    throw new Error(
      'not implemented — phase 63 (shared folder breadcrumb navigation requires Node read-chain)'
    );
  }, []);

  /**
   * Download a shared file using re-wrapped file keys.
   * @stub phase 63 — requires Node read-chain (NodeContent for file CID/key)
   */
  const downloadSharedFile = useCallback(async (_item: SealedChildRef) => {
    throw new Error('not implemented — phase 63 (shared file download requires Node read-chain)');
  }, []);

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
    hideSharedItem,
  };
}
