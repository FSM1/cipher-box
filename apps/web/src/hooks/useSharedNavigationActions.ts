/**
 * useSharedNavigationActions -- Navigation action handlers for shared content.
 *
 * Extracted from useSharedNavigation.ts. Contains all navigation callbacks
 * including key unwrapping during share/subfolder entry, download, and hide.
 */

import { useCallback, type MutableRefObject } from 'react';
import {
  decryptFolderMetadata,
  decryptFileMetadata,
  type FolderChild,
  type FolderEntry,
  type FilePointer,
  type EncryptedFolderMetadata,
  type EncryptedFileMetadata,
} from '@cipherbox/core';
import { unwrapKey, hexToBytes } from '@cipherbox/crypto';
import { ShareKeyCache } from '@cipherbox/sdk';
import { useAuthStore } from '../stores/auth.store';
import { useShareStore } from '../stores/share.store';
import { hideShare } from '../services/share.service';
import { resolveIpnsRecord } from '../services/ipns.service';
import { fetchFromIpfs } from '../lib/api/ipfs';
import { downloadFile, triggerBrowserDownload } from '../services/download.service';
import { useDownloadStore } from '../stores/download.store';
import { logger } from '../lib/logger';
import type { SharedListItem, SharedBreadcrumb } from './useSharedNavigation';

type NavStackEntry = {
  folderId: string;
  folderName: string;
  children: FolderChild[];
  folderKey: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint | null;
};

export type SharedNavigationActionsParams = {
  sharedItems: SharedListItem[];
  folderChildren: FolderChild[];
  folderKey: Uint8Array | null;
  breadcrumbs: SharedBreadcrumb[];
  currentShareId: string | null;
  permission: 'read' | 'write' | null;
  ipnsName: string | null;
  currentSequenceNumber: bigint | null;
  currentView: 'list' | 'folder' | 'file';
  // Refs
  folderChildrenRef: MutableRefObject<FolderChild[]>;
  sequenceNumberRef: MutableRefObject<bigint | null>;
  ipnsPrivateKeyRef: MutableRefObject<Uint8Array | null>;
  navStackRef: MutableRefObject<NavStackEntry[]>;
  shareKeysCacheRef: MutableRefObject<ShareKeyCache>;
  // State setters
  setCurrentView: (view: 'list' | 'folder' | 'file') => void;
  setCurrentShareId: (id: string | null) => void;
  setFolderChildren: (children: FolderChild[]) => void;
  setFolderKey: (key: Uint8Array | null) => void;
  setBreadcrumbs: (crumbs: SharedBreadcrumb[] | ((prev: SharedBreadcrumb[]) => SharedBreadcrumb[])) => void;
  setPermission: (perm: 'read' | 'write' | null) => void;
  setIpnsName: (name: string | null) => void;
  setCurrentSequenceNumber: (seq: bigint | null) => void;
  setIsLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setSharedItems: (updater: (prev: SharedListItem[]) => SharedListItem[]) => void;
  // Helpers from orchestrator
  clearPolling: () => void;
  zeroIpnsKey: () => void;
  getShareKeys: (shareId: string) => Promise<Array<{ keyType: string; itemId: string; encryptedKey: string }>>;
};

export function useSharedNavigationActions(p: SharedNavigationActionsParams) {
  /**
   * Navigate into a shared folder/file from the top-level list.
   */
  const navigateToShare = useCallback(
    async (shareId: string) => {
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) {
        p.setError('No keypair available');
        return;
      }

      const shareItem = p.sharedItems.find((s) => s.share.shareId === shareId);
      if (!shareItem) return;

      const share = shareItem.share;

      p.setIsLoading(true);
      p.setError(null);
      p.clearPolling();

      try {
        const itemKey = await unwrapKey(
          hexToBytes(share.encryptedKey),
          auth.vaultKeypair.privateKey,
        );

        if (share.itemType === 'folder') {
          let folderKeyStored = false;
          try {
            const resolved = await resolveIpnsRecord(share.ipnsName);
            if (!resolved) throw new Error('Could not resolve shared folder IPNS');

            const encryptedBytes = await fetchFromIpfs(resolved.cid);
            const encryptedJson = new TextDecoder().decode(encryptedBytes);
            const encrypted: EncryptedFolderMetadata = JSON.parse(encryptedJson);
            const metadata = await decryptFolderMetadata(encrypted, itemKey);

            if (share.permission === 'write' && share.encryptedIpnsKey) {
              try {
                const ipnsPrivKey = await unwrapKey(
                  hexToBytes(share.encryptedIpnsKey),
                  auth.vaultKeypair.privateKey,
                );
                p.ipnsPrivateKeyRef.current = ipnsPrivKey;
              } catch (err) {
                logger.error('[SharedNav] Failed to unwrap IPNS key for write share:', err);
              }
            }

            const children = metadata.children ?? [];
            const seqNum = BigInt(resolved.sequenceNumber);
            p.setCurrentView('folder');
            p.setCurrentShareId(shareId);
            p.setFolderChildren(children);
            p.folderChildrenRef.current = children;
            p.setFolderKey(itemKey);
            folderKeyStored = true;
            p.setBreadcrumbs([{ id: shareId, name: share.itemName }]);
            p.setPermission(p.ipnsPrivateKeyRef.current ? share.permission : 'read');
            p.setIpnsName(share.ipnsName);
            p.setCurrentSequenceNumber(seqNum);
            p.sequenceNumberRef.current = seqNum;
            p.navStackRef.current = [];
          } finally {
            if (!folderKeyStored) itemKey.fill(0);
          }
        } else {
          let folderKeyStored = false;
          try {
            if (share.permission === 'write' && share.encryptedIpnsKey) {
              try {
                const ipnsPrivKey = await unwrapKey(
                  hexToBytes(share.encryptedIpnsKey),
                  auth.vaultKeypair.privateKey,
                );
                p.ipnsPrivateKeyRef.current = ipnsPrivKey;
              } catch (err) {
                logger.error('[SharedNav] Failed to unwrap IPNS key for write file share:', err);
              }
            }
            p.setCurrentView('file');
            p.setCurrentShareId(shareId);
            p.setFolderKey(itemKey);
            folderKeyStored = true;
            p.setPermission(p.ipnsPrivateKeyRef.current ? share.permission : 'read');
            p.setIpnsName(share.ipnsName);
            p.setBreadcrumbs([{ id: shareId, name: share.itemName }]);
          } finally {
            if (!folderKeyStored) itemKey.fill(0);
          }
        }
      } catch (err) {
        logger.error('[SharedNav] Failed to navigate to shared item:', err);
        p.setError('Failed to open shared item');
      } finally {
        p.setIsLoading(false);
      }
    },
    [p.sharedItems, p.clearPolling],
  );

  /**
   * Navigate into a subfolder within a shared folder.
   */
  const navigateToSubfolder = useCallback(
    async (folderId: string, folderName: string) => {
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair || !p.currentShareId) return;

      p.setIsLoading(true);
      p.setError(null);
      p.clearPolling();

      try {
        const keys = await p.getShareKeys(p.currentShareId);
        const keyRecord = keys.find((k) => k.keyType === 'folder' && k.itemId === folderId);
        if (!keyRecord) throw new Error('No key available for this subfolder');

        const subfolderKey = await unwrapKey(
          hexToBytes(keyRecord.encryptedKey),
          auth.vaultKeypair.privateKey,
        );
        let subfolderKeyStored = false;

        try {
          const folderEntry = p.folderChildren.find(
            (c): c is FolderEntry => c.type === 'folder' && c.id === folderId,
          );
          if (!folderEntry) throw new Error('Subfolder not found in current children');

          const resolved = await resolveIpnsRecord(folderEntry.ipnsName);
          if (!resolved) throw new Error('Could not resolve subfolder IPNS');

          const encryptedBytes = await fetchFromIpfs(resolved.cid);
          const encryptedJson = new TextDecoder().decode(encryptedBytes);
          const encrypted: EncryptedFolderMetadata = JSON.parse(encryptedJson);
          const metadata = await decryptFolderMetadata(encrypted, subfolderKey);

          if (p.folderKey && p.ipnsName) {
            p.navStackRef.current.push({
              folderId: p.breadcrumbs[p.breadcrumbs.length - 1]?.id ?? '',
              folderName: p.breadcrumbs[p.breadcrumbs.length - 1]?.name ?? '',
              children: p.folderChildren,
              folderKey: p.folderKey,
              ipnsName: p.ipnsName,
              sequenceNumber: p.currentSequenceNumber,
            });
          }

          const children = metadata.children ?? [];
          const seqNum = BigInt(resolved.sequenceNumber);
          p.setFolderChildren(children);
          p.folderChildrenRef.current = children;
          p.setFolderKey(subfolderKey);
          subfolderKeyStored = true;
          p.setBreadcrumbs((prev) => [...prev, { id: folderId, name: folderName }]);
          p.setIpnsName(folderEntry.ipnsName);
          p.setCurrentSequenceNumber(seqNum);
          p.sequenceNumberRef.current = seqNum;

          if (p.permission === 'write' && p.currentShareId) {
            p.zeroIpnsKey();
            let restored = false;
            try {
              const subKeys = await p.getShareKeys(p.currentShareId);
              const ipnsKeyRecord = subKeys.find(
                (k) => k.keyType === 'folder-ipns' && k.itemId === folderId,
              );
              if (ipnsKeyRecord) {
                const ipnsPrivKey = await unwrapKey(
                  hexToBytes(ipnsKeyRecord.encryptedKey),
                  auth.vaultKeypair.privateKey,
                );
                p.ipnsPrivateKeyRef.current = ipnsPrivKey;
                restored = true;
              }
            } catch {
              // Couldn't get subfolder IPNS key
            }
            if (!restored) p.setPermission('read');
          }
        } finally {
          if (!subfolderKeyStored) subfolderKey.fill(0);
        }
      } catch (err) {
        logger.error('[SharedNav] Failed to navigate to subfolder:', err);
        p.setError('Failed to open subfolder');
      } finally {
        p.setIsLoading(false);
      }
    },
    [
      p.currentShareId,
      p.folderChildren,
      p.folderKey,
      p.breadcrumbs,
      p.getShareKeys,
      p.ipnsName,
      p.currentSequenceNumber,
      p.clearPolling,
      p.permission,
      p.zeroIpnsKey,
    ],
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
   * Restore the correct IPNS private key for the current depth.
   */
  const restoreIpnsKeyForDepth = useCallback(
    async (targetFolderId?: string) => {
      if (!p.currentShareId) return;
      const shareItem = p.sharedItems.find((s) => s.share.shareId === p.currentShareId);
      const share = shareItem?.share;
      if (share?.permission !== 'write') return;

      p.zeroIpnsKey();
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) return;

      try {
        if (!targetFolderId && share.encryptedIpnsKey) {
          const ipnsPrivKey = await unwrapKey(
            hexToBytes(share.encryptedIpnsKey),
            auth.vaultKeypair.privateKey,
          );
          p.ipnsPrivateKeyRef.current = ipnsPrivKey;
          p.setPermission('write');
        } else if (targetFolderId) {
          const keys = await p.getShareKeys(p.currentShareId);
          const ipnsKeyRecord = keys.find(
            (k) => k.keyType === 'folder-ipns' && k.itemId === targetFolderId,
          );
          if (ipnsKeyRecord) {
            const ipnsPrivKey = await unwrapKey(
              hexToBytes(ipnsKeyRecord.encryptedKey),
              auth.vaultKeypair.privateKey,
            );
            p.ipnsPrivateKeyRef.current = ipnsPrivKey;
            p.setPermission('write');
          } else {
            p.setPermission('read');
          }
        }
      } catch {
        // Couldn't restore — stay read-only
      }
    },
    [p.currentShareId, p.getShareKeys, p.sharedItems, p.zeroIpnsKey],
  );

  /**
   * Navigate up one level.
   */
  const navigateUp = useCallback(async () => {
    if (p.navStackRef.current.length > 0) {
      if (p.folderKey) p.folderKey.fill(0);
      const prev = p.navStackRef.current.pop()!;
      p.setFolderChildren(prev.children);
      p.folderChildrenRef.current = prev.children;
      p.setFolderKey(prev.folderKey);
      p.setBreadcrumbs((crumbs) => crumbs.slice(0, -1));
      p.setIpnsName(prev.ipnsName);
      p.setCurrentSequenceNumber(prev.sequenceNumber);
      p.sequenceNumberRef.current = prev.sequenceNumber;

      if (p.navStackRef.current.length === 0) {
        await restoreIpnsKeyForDepth();
      } else {
        await restoreIpnsKeyForDepth(prev.folderId);
      }
    } else if (p.currentView === 'folder' || p.currentView === 'file') {
      navigateToRoot();
    }
  }, [p.currentView, p.folderKey, navigateToRoot, restoreIpnsKeyForDepth]);

  /**
   * Navigate directly to a breadcrumb level.
   */
  const navigateToBreadcrumb = useCallback(
    async (crumbIndex: number) => {
      const popsNeeded = p.breadcrumbs.length - 1 - crumbIndex;
      if (popsNeeded <= 0) return;
      if (p.folderKey) p.folderKey.fill(0);
      for (let i = 0; i < popsNeeded - 1; i++) {
        const entry = p.navStackRef.current.pop();
        if (entry) entry.folderKey.fill(0);
      }
      const target = p.navStackRef.current.pop();
      if (target) {
        p.setFolderChildren(target.children);
        p.folderChildrenRef.current = target.children;
        p.setFolderKey(target.folderKey);
        p.setBreadcrumbs((crumbs) => crumbs.slice(0, crumbIndex + 1));
        p.setIpnsName(target.ipnsName);
        p.setCurrentSequenceNumber(target.sequenceNumber);
        p.sequenceNumberRef.current = target.sequenceNumber;

        if (p.navStackRef.current.length === 0) {
          await restoreIpnsKeyForDepth();
        } else {
          await restoreIpnsKeyForDepth(target.folderId);
        }
      }
    },
    [p.breadcrumbs, p.folderKey, restoreIpnsKeyForDepth],
  );

  /**
   * Download a shared file using re-wrapped file keys.
   */
  const downloadSharedFile = useCallback(
    async (item: FilePointer) => {
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair || !p.currentShareId || !p.folderKey) return;

      const downloadStore = useDownloadStore.getState();

      try {
        downloadStore.startDownload(item.name);

        const keys = await p.getShareKeys(p.currentShareId);

        const resolved = await resolveIpnsRecord(item.fileMetaIpnsName);
        if (!resolved) throw new Error('File metadata IPNS not found');

        const encryptedBytes = await fetchFromIpfs(resolved.cid);
        const encryptedJson = new TextDecoder().decode(encryptedBytes);
        const encrypted: EncryptedFileMetadata = JSON.parse(encryptedJson);
        const fileMeta = await decryptFileMetadata(encrypted, p.folderKey);

        const fileKeyRecord = keys.find((k) => k.keyType === 'file' && k.itemId === item.id);
        if (!fileKeyRecord) {
          throw new Error('File key not available — the folder owner may need to re-share');
        }
        const wrappedKey = fileKeyRecord.encryptedKey;

        const plaintext = await downloadFile(
          {
            cid: fileMeta.cid,
            iv: fileMeta.fileIv,
            wrappedKey,
            originalName: item.name,
            encryptionMode: fileMeta.encryptionMode,
          },
          auth.vaultKeypair.privateKey,
        );

        downloadStore.setDecrypting();
        triggerBrowserDownload(plaintext, item.name);
        downloadStore.setSuccess();
      } catch (err) {
        const message = (err as Error).message || 'Download failed';
        downloadStore.setError(message);
        logger.error('[SharedNav] Shared file download failed:', err);
      }
    },
    [p.currentShareId, p.folderKey, p.getShareKeys],
  );

  /**
   * Hide a shared item from the user's view.
   */
  const hideSharedItem = useCallback(async (shareId: string) => {
    try {
      await hideShare(shareId);
      useShareStore.getState().removeReceivedShare(shareId);
      p.setSharedItems((prev) => prev.filter((s) => s.share.shareId !== shareId));
    } catch (err) {
      logger.error('[SharedNav] Failed to hide share:', err);
      p.setError('Failed to hide shared item');
    }
  }, []);

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
