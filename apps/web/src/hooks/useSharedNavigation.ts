/**
 * useSharedNavigation -- Navigation hook for browsing shared content.
 *
 * Similar to useFolderNavigation but with a different key source:
 * - Top level: shares received via share records
 * - Folder browsing: re-wrapped keys from share_keys table
 * - File download: re-wrapped fileKey from share_keys table
 *
 * Security: All keys are ECIES-wrapped for the current user.
 * The server never sees plaintext keys.
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import {
  unwrapKey,
  hexToBytes,
  decryptFolderMetadata,
  decryptFileMetadata,
  type FolderChild,
  type FolderEntry,
  type FilePointer,
  type EncryptedFolderMetadata,
  type EncryptedFileMetadata,
} from '@cipherbox/crypto';
import { useAuthStore } from '../stores/auth.store';
import { useShareStore, type ReceivedShare } from '../stores/share.store';
import { fetchReceivedShares, fetchShareKeys, hideShare } from '../services/share.service';
import { resolveIpnsRecord } from '../services/ipns.service';
import { fetchFromIpfs } from '../lib/api/ipfs';
import { downloadFile, triggerBrowserDownload } from '../services/download.service';
import { useDownloadStore } from '../stores/download.store';

/**
 * Breadcrumb entry for shared navigation.
 */
export type SharedBreadcrumb = {
  id: string;
  name: string;
};

/**
 * A shared item displayed in the top-level shared list.
 * Extends the original FolderChild with sharing metadata.
 */
export type SharedListItem = {
  share: ReceivedShare;
  /** Resolved folder children (for folders), or null (for files / unresolved) */
  children: FolderChild[] | null;
  /** Folder key for this shared item (decrypted from share record) */
  folderKey: Uint8Array | null;
};

type SharedView = 'list' | 'folder';

type UseSharedNavigationReturn = {
  currentView: SharedView;
  currentShareId: string | null;
  sharedItems: SharedListItem[];
  folderChildren: FolderChild[];
  folderKey: Uint8Array | null;
  breadcrumbs: SharedBreadcrumb[];
  isLoading: boolean;
  error: string | null;
  navigateToShare: (shareId: string) => Promise<void>;
  navigateToSubfolder: (folderId: string, folderName: string) => Promise<void>;
  navigateUp: () => void;
  navigateToRoot: () => void;
  downloadSharedFile: (item: FilePointer) => Promise<void>;
  hideSharedItem: (shareId: string) => Promise<void>;
};

/**
 * Hook for browsing shared content.
 *
 * Manages the "Shared with me" browsing experience.
 * Top-level view shows received shares as a flat list.
 * Clicking a shared folder navigates into it using re-wrapped keys.
 */
export function useSharedNavigation(): UseSharedNavigationReturn {
  const [currentView, setCurrentView] = useState<SharedView>('list');
  const [currentShareId, setCurrentShareId] = useState<string | null>(null);
  const [sharedItems, setSharedItems] = useState<SharedListItem[]>([]);
  const [folderChildren, setFolderChildren] = useState<FolderChild[]>([]);
  const [folderKey, setFolderKey] = useState<Uint8Array | null>(null);
  const [breadcrumbs, setBreadcrumbs] = useState<SharedBreadcrumb[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Navigation stack for folder browsing within a share
  const navStackRef = useRef<
    Array<{
      folderId: string;
      folderName: string;
      children: FolderChild[];
      folderKey: Uint8Array;
    }>
  >([]);

  // Cache share keys per shareId with TTL to avoid refetching
  const shareKeysCache = useRef<
    Map<
      string,
      {
        keys: Array<{ keyType: 'file' | 'folder'; itemId: string; encryptedKey: string }>;
        fetchedAt: number;
      }
    >
  >(new Map());

  /**
   * Load received shares on mount.
   */
  useEffect(() => {
    let cancelled = false;

    async function loadShares() {
      setIsLoading(true);
      setError(null);

      try {
        const shares = await fetchReceivedShares();
        if (cancelled) return;

        useShareStore.getState().setReceivedShares(shares);

        const items: SharedListItem[] = shares.map((share) => ({
          share,
          children: null,
          folderKey: null,
        }));

        setSharedItems(items);
      } catch (err) {
        if (cancelled) return;
        console.error('Failed to load shared items:', err);
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
      // Zero all decrypted folder keys on unmount
      setFolderKey((prev) => {
        if (prev) prev.fill(0);
        return null;
      });
      for (const entry of navStackRef.current) {
        entry.folderKey.fill(0);
      }
      navStackRef.current = [];
    };
  }, []);

  /** Cache TTL for share keys (60 seconds). */
  const SHARE_KEYS_CACHE_TTL = 60_000;

  /**
   * Get share keys for a share, with TTL-based caching.
   */
  const getShareKeys = useCallback(async (shareId: string) => {
    const cached = shareKeysCache.current.get(shareId);
    if (cached && Date.now() - cached.fetchedAt < SHARE_KEYS_CACHE_TTL) {
      return cached.keys;
    }

    const keys = await fetchShareKeys(shareId);
    shareKeysCache.current.set(shareId, { keys, fetchedAt: Date.now() });
    return keys;
  }, []);

  /**
   * Navigate into a shared folder from the top-level list.
   */
  const navigateToShare = useCallback(
    async (shareId: string) => {
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) {
        setError('No keypair available');
        return;
      }

      const shareItem = sharedItems.find((s) => s.share.shareId === shareId);
      if (!shareItem) return;

      const share = shareItem.share;

      setIsLoading(true);
      setError(null);

      try {
        // Unwrap the shared item's key with our private key
        const itemKey = await unwrapKey(
          hexToBytes(share.encryptedKey),
          auth.vaultKeypair.privateKey
        );

        if (share.itemType === 'folder') {
          // Resolve folder IPNS to get metadata
          const resolved = await resolveIpnsRecord(share.ipnsName);
          if (!resolved) {
            throw new Error('Could not resolve shared folder IPNS');
          }

          // Fetch and decrypt folder metadata
          const encryptedBytes = await fetchFromIpfs(resolved.cid);
          const encryptedJson = new TextDecoder().decode(encryptedBytes);
          const encrypted: EncryptedFolderMetadata = JSON.parse(encryptedJson);
          const metadata = await decryptFolderMetadata(encrypted, itemKey);

          // Set folder state
          setCurrentView('folder');
          setCurrentShareId(shareId);
          setFolderChildren(metadata.children ?? []);
          setFolderKey(itemKey);
          setBreadcrumbs([{ id: shareId, name: share.itemName }]);
          navStackRef.current = [];
        } else {
          // For files, trigger download directly
          // itemKey is the parent folder key; downloadSharedFileFromShare unwraps its own copy
          itemKey.fill(0);
          await downloadSharedFileFromShare(share, auth.vaultKeypair.privateKey);
        }
      } catch (err) {
        console.error('Failed to navigate to shared item:', err);
        setError('Failed to open shared item');
      } finally {
        setIsLoading(false);
      }
    },
    [sharedItems]
  );

  /**
   * Navigate into a subfolder within a shared folder.
   */
  const navigateToSubfolder = useCallback(
    async (folderId: string, folderName: string) => {
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair || !currentShareId) return;

      setIsLoading(true);
      setError(null);

      try {
        // Get re-wrapped keys for this share
        const keys = await getShareKeys(currentShareId);

        // Find the re-wrapped folder key for this subfolder
        const keyRecord = keys.find((k) => k.keyType === 'folder' && k.itemId === folderId);
        if (!keyRecord) {
          throw new Error('No key available for this subfolder');
        }

        // Unwrap the subfolder key
        const subfolderKey = await unwrapKey(
          hexToBytes(keyRecord.encryptedKey),
          auth.vaultKeypair.privateKey
        );

        // Find the subfolder entry to get its IPNS name
        const folderEntry = folderChildren.find(
          (c): c is FolderEntry => c.type === 'folder' && c.id === folderId
        );
        if (!folderEntry) {
          throw new Error('Subfolder not found in current children');
        }

        // Resolve subfolder IPNS
        const resolved = await resolveIpnsRecord(folderEntry.ipnsName);
        if (!resolved) {
          throw new Error('Could not resolve subfolder IPNS');
        }

        // Fetch and decrypt subfolder metadata
        const encryptedBytes = await fetchFromIpfs(resolved.cid);
        const encryptedJson = new TextDecoder().decode(encryptedBytes);
        const encrypted: EncryptedFolderMetadata = JSON.parse(encryptedJson);
        const metadata = await decryptFolderMetadata(encrypted, subfolderKey);

        // Push current state to nav stack
        if (folderKey) {
          navStackRef.current.push({
            folderId: breadcrumbs[breadcrumbs.length - 1]?.id ?? '',
            folderName: breadcrumbs[breadcrumbs.length - 1]?.name ?? '',
            children: folderChildren,
            folderKey,
          });
        }

        // Update state
        setFolderChildren(metadata.children ?? []);
        setFolderKey(subfolderKey);
        setBreadcrumbs((prev) => [...prev, { id: folderId, name: folderName }]);
      } catch (err) {
        console.error('Failed to navigate to subfolder:', err);
        setError('Failed to open subfolder');
      } finally {
        setIsLoading(false);
      }
    },
    [currentShareId, folderChildren, folderKey, breadcrumbs, getShareKeys]
  );

  /**
   * Navigate up one level.
   */
  const navigateUp = useCallback(() => {
    if (navStackRef.current.length > 0) {
      // Zero current folder key before replacing
      if (folderKey) folderKey.fill(0);
      // Pop from nav stack
      const prev = navStackRef.current.pop()!;
      setFolderChildren(prev.children);
      setFolderKey(prev.folderKey);
      setBreadcrumbs((crumbs) => crumbs.slice(0, -1));
    } else if (currentView === 'folder') {
      // Back to top-level list
      navigateToRoot();
    }
  }, [currentView, folderKey]);

  /**
   * Navigate back to the top-level shared list.
   * Zeroes all decrypted folder keys from memory before clearing state.
   */
  const navigateToRoot = useCallback(() => {
    // Zero current folder key
    if (folderKey) folderKey.fill(0);
    // Zero all nav stack folder keys
    for (const entry of navStackRef.current) {
      entry.folderKey.fill(0);
    }
    setCurrentView('list');
    setCurrentShareId(null);
    setFolderChildren([]);
    setFolderKey(null);
    setBreadcrumbs([]);
    navStackRef.current = [];
    setError(null);
  }, [folderKey]);

  /**
   * Download a shared file from the top-level list.
   * The share's encryptedKey wraps the parent folder key (needed to decrypt file metadata).
   * The actual file key is stored as a child key in share_keys.
   */
  async function downloadSharedFileFromShare(
    share: ReceivedShare,
    privateKey: Uint8Array
  ): Promise<void> {
    if (share.itemType !== 'file') return;

    const downloadStore = useDownloadStore.getState();

    try {
      downloadStore.startDownload(share.itemName);

      // Unwrap the parent folder key from the share record
      const parentFolderKey = await unwrapKey(hexToBytes(share.encryptedKey), privateKey);

      let fileMeta: Awaited<ReturnType<typeof decryptFileMetadata>>;
      try {
        // Resolve file IPNS metadata and decrypt with parent folder key
        const resolved = await resolveIpnsRecord(share.ipnsName);
        if (!resolved) {
          throw new Error('File metadata IPNS not found');
        }

        const encryptedBytes = await fetchFromIpfs(resolved.cid);
        const encryptedJson = new TextDecoder().decode(encryptedBytes);
        const encrypted: EncryptedFileMetadata = JSON.parse(encryptedJson);
        fileMeta = await decryptFileMetadata(encrypted, parentFolderKey);
      } finally {
        parentFolderKey.fill(0);
      }

      // Get the re-wrapped file key from share_keys
      const keys = await fetchShareKeys(share.shareId);
      const fileKeyRecord = keys.find((k) => k.keyType === 'file');
      if (!fileKeyRecord) {
        throw new Error('No re-wrapped file key available for this file');
      }

      // Download and decrypt using the re-wrapped file key
      const plaintext = await downloadFile(
        {
          cid: fileMeta.cid,
          iv: fileMeta.fileIv,
          wrappedKey: fileKeyRecord.encryptedKey,
          originalName: share.itemName,
          encryptionMode: fileMeta.encryptionMode,
        },
        privateKey
      );

      downloadStore.setDecrypting();
      triggerBrowserDownload(plaintext, share.itemName);
      downloadStore.setSuccess();
    } catch (err) {
      const message = (err as Error).message || 'Download failed';
      downloadStore.setError(message);
      console.error('Shared file download failed:', err);
    }
  }

  /**
   * Download a shared file from within a shared folder.
   * Uses re-wrapped file keys from share_keys.
   */
  const downloadSharedFile = useCallback(
    async (item: FilePointer) => {
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair || !currentShareId || !folderKey) return;

      const downloadStore = useDownloadStore.getState();

      try {
        downloadStore.startDownload(item.name);

        // Get share keys for file key lookup
        const keys = await getShareKeys(currentShareId);

        // First resolve the file metadata using the parent folder key
        const resolved = await resolveIpnsRecord(item.fileMetaIpnsName);
        if (!resolved) {
          throw new Error('File metadata IPNS not found');
        }

        const encryptedBytes = await fetchFromIpfs(resolved.cid);
        const encryptedJson = new TextDecoder().decode(encryptedBytes);
        const encrypted: EncryptedFileMetadata = JSON.parse(encryptedJson);
        const fileMeta = await decryptFileMetadata(encrypted, folderKey);

        // Look for a re-wrapped file key in share_keys
        const fileKeyRecord = keys.find((k) => k.keyType === 'file' && k.itemId === item.id);

        if (!fileKeyRecord) {
          throw new Error('No re-wrapped file key available for this file');
        }

        // Use re-wrapped file key from share_keys
        // downloadFile handles unwrapping internally via wrappedKey + privateKey
        const plaintext = await downloadFile(
          {
            cid: fileMeta.cid,
            iv: fileMeta.fileIv,
            wrappedKey: fileKeyRecord.encryptedKey,
            originalName: item.name,
            encryptionMode: fileMeta.encryptionMode,
          },
          auth.vaultKeypair.privateKey
        );

        downloadStore.setDecrypting();
        triggerBrowserDownload(plaintext, item.name);
        downloadStore.setSuccess();
      } catch (err) {
        const message = (err as Error).message || 'Download failed';
        downloadStore.setError(message);
        console.error('Shared file download failed:', err);
      }
    },
    [currentShareId, folderKey, getShareKeys]
  );

  /**
   * Hide a shared item from the user's view.
   */
  const hideSharedItem = useCallback(async (shareId: string) => {
    try {
      await hideShare(shareId);
      useShareStore.getState().removeReceivedShare(shareId);
      setSharedItems((prev) => prev.filter((s) => s.share.shareId !== shareId));
    } catch (err) {
      console.error('Failed to hide share:', err);
      setError('Failed to hide shared item');
    }
  }, []);

  return {
    currentView,
    currentShareId,
    sharedItems,
    folderChildren,
    folderKey,
    breadcrumbs,
    isLoading,
    error,
    navigateToShare,
    navigateToSubfolder,
    navigateUp,
    navigateToRoot,
    downloadSharedFile,
    hideSharedItem,
  };
}
