/**
 * useSharedNavigation -- Navigation hook for browsing shared content.
 *
 * Similar to useFolderNavigation but with a different key source:
 * - Top level: shares received via share records
 * - Folder browsing: re-wrapped keys from share_keys table
 * - File download: re-wrapped fileKey from share_keys table
 *
 * Write-share recipients additionally get:
 * - IPNS private key unwrapping for publishing changes
 * - Upload, mkdir, rename, delete operations with conflict retry
 * - 30s sync polling for the currently-viewed shared folder
 * - Silent revocation handling (badge transitions [RW] -> [RO])
 *
 * Security: All keys are ECIES-wrapped for the current user.
 * The server never sees plaintext keys.
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import {
  decryptFolderMetadata,
  decryptFileMetadata,
  encryptFolderMetadata,
  encryptFileMetadata,
  generateFileIpnsKeypair,
  createIpnsRecord,
  marshalIpnsRecord,
  type FolderChild,
  type FolderEntry,
  type FilePointer,
  type FileMetadata,
  type FolderMetadata,
  type EncryptedFolderMetadata,
  type EncryptedFileMetadata,
} from '@cipherbox/core';
import { unwrapKey, wrapKey, hexToBytes, generateRandomBytes, bytesToHex } from '@cipherbox/crypto';
import { useAuthStore } from '../stores/auth.store';
import { useShareStore, type ReceivedShare } from '../stores/share.store';
import {
  fetchReceivedShares,
  fetchShareKeys,
  hideShare,
  addShareKeys,
} from '../services/share.service';
import {
  resolveIpnsRecord,
  createAndPublishIpnsRecord,
  batchPublishIpnsRecords,
} from '../services/ipns.service';
import { fetchFromIpfs, addToIpfs } from '../lib/api/ipfs';
import { downloadFile, triggerBrowserDownload } from '../services/download.service';
import { useDownloadStore } from '../stores/download.store';
import { withConflictRetry } from './folder-helpers';

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
 * Check if an error is a 403 Forbidden (write access revoked).
 */
function isForbiddenError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const e = error as Record<string, unknown>;
  return e.status === 403;
}

/** Parse a 0x-prefixed or bare hex public key string into bytes. */
function parsePublicKey(keyHex: string): Uint8Array {
  const hex = keyHex.startsWith('0x') ? keyHex.slice(2) : keyHex;
  return hexToBytes(hex);
}

/** Safe base64 encoding that avoids call stack overflow from spread operator. */
function uint8ToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

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
  const shareKeysCache = useRef<
    Map<
      string,
      {
        keys: Array<{
          keyType: 'file' | 'folder' | 'file-ipns' | 'folder-ipns';
          itemId: string;
          encryptedKey: string;
        }>;
        fetchedAt: number;
      }
    >
  >(new Map());

  // Polling interval ref for 30s sync
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  /**
   * Zero the IPNS private key and clear the ref.
   */
  const zeroIpnsKey = useCallback(() => {
    if (ipnsPrivateKeyRef.current) {
      ipnsPrivateKeyRef.current.fill(0);
      ipnsPrivateKeyRef.current = null;
    }
  }, []);

  /**
   * Clear polling interval.
   */
  const clearPolling = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
  }, []);

  /**
   * Handle silent revocation: transition from write to read-only.
   */
  const handleRevocation = useCallback(
    (showError?: boolean) => {
      zeroIpnsKey();
      setPermission('read');
      if (showError) {
        setError('> write access revoked -- folder is now read-only');
      }
    },
    [zeroIpnsKey]
  );

  /**
   * Refresh folder contents from IPNS (used by polling and after write ops).
   * Returns the refreshed children, or null on failure.
   */
  const refreshFolderContents = useCallback(
    async (folderIpnsName: string, currentFolderKey: Uint8Array): Promise<FolderChild[] | null> => {
      try {
        const resolved = await resolveIpnsRecord(folderIpnsName);
        if (!resolved) return null;

        const encryptedBytes = await fetchFromIpfs(resolved.cid);
        const encryptedJson = new TextDecoder().decode(encryptedBytes);
        const encrypted: EncryptedFolderMetadata = JSON.parse(encryptedJson);
        const metadata = await decryptFolderMetadata(encrypted, currentFolderKey);

        const children = metadata.children ?? [];
        const seqNum = BigInt(resolved.sequenceNumber);
        setFolderChildren(children);
        folderChildrenRef.current = children;
        setCurrentSequenceNumber(seqNum);
        sequenceNumberRef.current = seqNum;
        return children;
      } catch {
        return null;
      }
    },
    []
  );

  /**
   * Load received shares on mount.
   */
  useEffect(() => {
    let cancelled = false;

    async function loadShares() {
      setIsLoading(true);
      setError(null);

      try {
        // Paginate through all received shares (API max 100 per page)
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
      zeroIpnsKey();
      clearPolling();
      shareKeysCache.current.clear();
    };
  }, [zeroIpnsKey, clearPolling]);

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
      clearPolling();

      try {
        // Unwrap the shared item's key with our private key
        const itemKey = await unwrapKey(
          hexToBytes(share.encryptedKey),
          auth.vaultKeypair.privateKey
        );

        if (share.itemType === 'folder') {
          let folderKeyStored = false;
          try {
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

            // Unwrap IPNS private key for write shares
            if (share.permission === 'write' && share.encryptedIpnsKey) {
              try {
                const ipnsPrivKey = await unwrapKey(
                  hexToBytes(share.encryptedIpnsKey),
                  auth.vaultKeypair.privateKey
                );
                ipnsPrivateKeyRef.current = ipnsPrivKey;
              } catch (err) {
                console.error('Failed to unwrap IPNS key for write share:', err);
                // Fall back to read-only if IPNS key unwrap fails
              }
            }

            // Set folder state (sync refs for retry closures — C-01)
            const children = metadata.children ?? [];
            const seqNum = BigInt(resolved.sequenceNumber);
            setCurrentView('folder');
            setCurrentShareId(shareId);
            setFolderChildren(children);
            folderChildrenRef.current = children;
            setFolderKey(itemKey);
            folderKeyStored = true;
            setBreadcrumbs([{ id: shareId, name: share.itemName }]);
            setPermission(ipnsPrivateKeyRef.current ? share.permission : 'read');
            setIpnsName(share.ipnsName);
            setCurrentSequenceNumber(seqNum);
            sequenceNumberRef.current = seqNum;
            navStackRef.current = [];
          } finally {
            if (!folderKeyStored) itemKey.fill(0);
          }
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
    [sharedItems, clearPolling]
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
      clearPolling();

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
        let subfolderKeyStored = false;

        try {
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
          if (folderKey && ipnsName) {
            navStackRef.current.push({
              folderId: breadcrumbs[breadcrumbs.length - 1]?.id ?? '',
              folderName: breadcrumbs[breadcrumbs.length - 1]?.name ?? '',
              children: folderChildren,
              folderKey,
              ipnsName,
              sequenceNumber: currentSequenceNumber,
            });
          }

          // Update state + refs
          const children = metadata.children ?? [];
          const seqNum = BigInt(resolved.sequenceNumber);
          setFolderChildren(children);
          folderChildrenRef.current = children;
          setFolderKey(subfolderKey);
          subfolderKeyStored = true;
          setBreadcrumbs((prev) => [...prev, { id: folderId, name: folderName }]);
          setIpnsName(folderEntry.ipnsName);
          setCurrentSequenceNumber(seqNum);
          sequenceNumberRef.current = seqNum;

          // For write-share recipients: unwrap the subfolder's IPNS private key
          // from share_keys (folder-ipns) so write operations work at any depth.
          if (permission === 'write' && currentShareId) {
            zeroIpnsKey(); // Zero parent key before replacing
            let restored = false;
            try {
              const subKeys = await getShareKeys(currentShareId);
              const ipnsKeyRecord = subKeys.find(
                (k) => k.keyType === 'folder-ipns' && k.itemId === folderId
              );
              if (ipnsKeyRecord) {
                const ipnsPrivKey = await unwrapKey(
                  hexToBytes(ipnsKeyRecord.encryptedKey),
                  auth.vaultKeypair.privateKey
                );
                ipnsPrivateKeyRef.current = ipnsPrivKey;
                restored = true;
              }
            } catch {
              // Couldn't get subfolder IPNS key from share_keys
            }
            if (!restored) {
              // No subfolder IPNS key available — drop to read-only for this subfolder
              setPermission('read');
            }
          }
        } finally {
          if (!subfolderKeyStored) subfolderKey.fill(0);
        }
      } catch (err) {
        console.error('Failed to navigate to subfolder:', err);
        setError('Failed to open subfolder');
      } finally {
        setIsLoading(false);
      }
    },
    [
      currentShareId,
      folderChildren,
      folderKey,
      breadcrumbs,
      getShareKeys,
      ipnsName,
      currentSequenceNumber,
      clearPolling,
      permission,
      zeroIpnsKey,
    ]
  );

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
    // Zero IPNS private key
    zeroIpnsKey();
    // Clear polling
    clearPolling();
    setCurrentView('list');
    setCurrentShareId(null);
    setFolderChildren([]);
    setFolderKey(null);
    setBreadcrumbs([]);
    setPermission(null);
    setIpnsName(null);
    setCurrentSequenceNumber(null);
    navStackRef.current = [];
    setError(null);
  }, [folderKey, zeroIpnsKey, clearPolling]);

  /**
   * Navigate up one level.
   */
  /**
   * Restore the correct IPNS private key for the current depth.
   * Root level: unwrap from share record. Subfolder level: unwrap from folder-ipns share_key.
   */
  const restoreIpnsKeyForDepth = useCallback(
    async (targetFolderId?: string) => {
      if (!currentShareId) return;
      const shareItem = sharedItems.find((s) => s.share.shareId === currentShareId);
      const share = shareItem?.share;
      if (share?.permission !== 'write') return;

      zeroIpnsKey();
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) return;

      try {
        if (!targetFolderId && share.encryptedIpnsKey) {
          // Root share level — unwrap from share record
          const ipnsPrivKey = await unwrapKey(
            hexToBytes(share.encryptedIpnsKey),
            auth.vaultKeypair.privateKey
          );
          ipnsPrivateKeyRef.current = ipnsPrivKey;
          setPermission('write');
        } else if (targetFolderId) {
          // Subfolder level — unwrap from folder-ipns share_key
          const keys = await getShareKeys(currentShareId);
          const ipnsKeyRecord = keys.find(
            (k) => k.keyType === 'folder-ipns' && k.itemId === targetFolderId
          );
          if (ipnsKeyRecord) {
            const ipnsPrivKey = await unwrapKey(
              hexToBytes(ipnsKeyRecord.encryptedKey),
              auth.vaultKeypair.privateKey
            );
            ipnsPrivateKeyRef.current = ipnsPrivKey;
            setPermission('write');
          } else {
            setPermission('read');
          }
        }
      } catch {
        // Couldn't restore — stay read-only
      }
    },
    [currentShareId, getShareKeys, sharedItems, zeroIpnsKey]
  );

  const navigateUp = useCallback(async () => {
    if (navStackRef.current.length > 0) {
      // Zero current folder key before replacing
      if (folderKey) folderKey.fill(0);
      // Pop from nav stack
      const prev = navStackRef.current.pop()!;
      setFolderChildren(prev.children);
      folderChildrenRef.current = prev.children;
      setFolderKey(prev.folderKey);
      setBreadcrumbs((crumbs) => crumbs.slice(0, -1));
      setIpnsName(prev.ipnsName);
      setCurrentSequenceNumber(prev.sequenceNumber);
      sequenceNumberRef.current = prev.sequenceNumber;

      // Restore IPNS key: root level (no stack) or subfolder (top of remaining stack)
      if (navStackRef.current.length === 0) {
        await restoreIpnsKeyForDepth(); // root level
      } else {
        await restoreIpnsKeyForDepth(prev.folderId);
      }
    } else if (currentView === 'folder') {
      // Back to top-level list
      navigateToRoot();
    }
  }, [currentView, folderKey, navigateToRoot, restoreIpnsKeyForDepth]);

  /**
   * Navigate directly to a breadcrumb level, zeroing all intermediate keys.
   * More efficient than calling navigateUp() in a loop.
   */
  const navigateToBreadcrumb = useCallback(
    async (crumbIndex: number) => {
      const popsNeeded = breadcrumbs.length - 1 - crumbIndex;
      if (popsNeeded <= 0) return;
      // Zero the current folder key
      if (folderKey) folderKey.fill(0);
      // Zero and discard all intermediate keys
      for (let i = 0; i < popsNeeded - 1; i++) {
        const entry = navStackRef.current.pop();
        if (entry) entry.folderKey.fill(0);
      }
      // Restore the target level
      const target = navStackRef.current.pop();
      if (target) {
        setFolderChildren(target.children);
        folderChildrenRef.current = target.children;
        setFolderKey(target.folderKey);
        setBreadcrumbs((crumbs) => crumbs.slice(0, crumbIndex + 1));
        setIpnsName(target.ipnsName);
        setCurrentSequenceNumber(target.sequenceNumber);
        sequenceNumberRef.current = target.sequenceNumber;

        // Restore IPNS key for the target depth
        if (navStackRef.current.length === 0) {
          await restoreIpnsKeyForDepth(); // root level
        } else {
          await restoreIpnsKeyForDepth(target.folderId);
        }
      }
    },
    [breadcrumbs, folderKey, restoreIpnsKeyForDepth]
  );

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

        // Look for a re-wrapped file key in share_keys,
        // falling back to fileKeyEncrypted from metadata (for files uploaded by current user)
        const fileKeyRecord = keys.find((k) => k.keyType === 'file' && k.itemId === item.id);
        if (!fileKeyRecord) {
          throw new Error('File key not available — the folder owner may need to re-share');
        }
        const wrappedKey = fileKeyRecord.encryptedKey;

        // downloadFile handles unwrapping internally via wrappedKey + privateKey
        const plaintext = await downloadFile(
          {
            cid: fileMeta.cid,
            iv: fileMeta.fileIv,
            wrappedKey,
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

  // -------------------------------------------------------------------------
  // Write operation helpers for write-share recipients
  // -------------------------------------------------------------------------

  /**
   * Re-sync the current shared folder for conflict retry.
   * Updates folderChildren and currentSequenceNumber in-place.
   */
  const resyncSharedFolder = useCallback(async () => {
    if (!ipnsName || !folderKey) return;
    await refreshFolderContents(ipnsName, folderKey);
  }, [ipnsName, folderKey, refreshFolderContents]);

  /**
   * Publish updated folder metadata to IPNS using the write-share IPNS key.
   * Returns the new sequence number on success.
   */
  const publishSharedFolderMetadata = useCallback(
    async (
      children: FolderChild[],
      currentFolderKey: Uint8Array,
      folderIpnsName: string,
      ipnsPrivKey: Uint8Array,
      seqNum: bigint
    ): Promise<bigint> => {
      // 1. Create folder metadata
      const metadata: FolderMetadata = {
        version: 'v2',
        children,
      };

      // 2. Encrypt metadata with folder key
      const encrypted = await encryptFolderMetadata(metadata, currentFolderKey);

      // 3. Upload to IPFS via backend relay
      const blob = new Blob([JSON.stringify(encrypted)], {
        type: 'application/json',
      });
      const { cid } = await addToIpfs(blob);

      // 4. Publish IPNS record
      const newSeq = seqNum + 1n;
      await createAndPublishIpnsRecord({
        ipnsPrivateKey: ipnsPrivKey,
        ipnsName: folderIpnsName,
        metadataCid: cid,
        sequenceNumber: newSeq,
        expectedSequenceNumber: seqNum.toString(),
      });

      return newSeq;
    },
    []
  );

  /**
   * Wrap a write operation with 403 revocation detection.
   * If 403 is received, transitions to read-only silently.
   */
  const withRevocationGuard = useCallback(
    async <T>(operation: () => Promise<T>): Promise<T> => {
      try {
        return await operation();
      } catch (err) {
        if (isForbiddenError(err)) {
          handleRevocation(true);
          throw new Error('> write access revoked -- folder is now read-only');
        }
        throw err;
      }
    },
    [handleRevocation]
  );

  /**
   * Upload a file to the currently-viewed write-shared folder.
   * Creates a proper per-file IPNS metadata record (same as owner uploads).
   */
  const uploadFileHandler = useCallback(
    async (file: File) => {
      const currentIpnsKey = ipnsPrivateKeyRef.current;
      const currentFolderKey = folderKey;
      const currentIpnsName = ipnsName;
      const seqNum = currentSequenceNumber;

      if (!currentIpnsKey || !currentFolderKey || !currentIpnsName || seqNum === null) {
        setError('Write access not available');
        return;
      }

      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) {
        setError('No keypair available');
        return;
      }

      // Get the owner's public key from the share record
      const shareItem = sharedItems.find((s) => s.share.shareId === currentShareId);
      if (!shareItem) {
        setError('Share not found');
        return;
      }
      const ownerPublicKey = parsePublicKey(shareItem.share.sharerPublicKey);

      setIsLoading(true);
      setError(null);

      try {
        await withRevocationGuard(async () => {
          // Read file content
          const data = new Uint8Array(await file.arrayBuffer());

          // Encrypt file content with AES-256-GCM
          const { encryptAesGcm, generateFileKey, generateIv } = await import('@cipherbox/crypto');

          const fileKey = generateFileKey();
          const iv = generateIv();

          try {
            const ciphertext = await encryptAesGcm(data, fileKey, iv);

            // Upload encrypted content to IPFS
            const fileBlob = new Blob([new Uint8Array(ciphertext)], {
              type: 'application/octet-stream',
            });
            const { cid: contentCid } = await addToIpfs(fileBlob);

            // Wrap file key with owner's public key for file metadata
            const ownerWrappedKey = await wrapKey(fileKey, ownerPublicKey);
            const fileKeyEncrypted = bytesToHex(ownerWrappedKey);

            // Generate IPNS keypair for this file's metadata record
            // Inline instead of using createFileMetadata so we can wrap with both keys
            const fileId = crypto.randomUUID();
            const mimeType = file.type || 'application/octet-stream';
            const ipnsKeypair = await generateFileIpnsKeypair();

            try {
              // Wrap IPNS private key with owner's key (stored in FilePointer — owner can update)
              const ownerWrappedIpnsKey = await wrapKey(ipnsKeypair.privateKey, ownerPublicKey);
              const ipnsPrivateKeyEncrypted = bytesToHex(ownerWrappedIpnsKey);

              // Wrap IPNS private key with recipient's key (stored in share_keys — recipient can update)
              const recipientWrappedIpnsKey = await wrapKey(
                ipnsKeypair.privateKey,
                auth.vaultKeypair!.publicKey
              );

              // Create and encrypt file metadata
              const now = Date.now();
              const fileMeta: FileMetadata = {
                version: 'v1',
                cid: contentCid,
                fileKeyEncrypted,
                fileIv: bytesToHex(iv),
                size: data.length,
                mimeType,
                encryptionMode: 'GCM',
                createdAt: now,
                modifiedAt: now,
              };
              const encrypted = await encryptFileMetadata(fileMeta, currentFolderKey);

              // Upload encrypted metadata to IPFS
              const metaBlob = new Blob([JSON.stringify(encrypted)], { type: 'application/json' });
              const { cid: metadataCid } = await addToIpfs(metaBlob);

              // Create and publish IPNS record
              const ipnsLifetimeMs = 24 * 60 * 60 * 1000;
              const record = await createIpnsRecord(
                ipnsKeypair.privateKey,
                `/ipfs/${metadataCid}`,
                1n,
                ipnsLifetimeMs
              );
              const recordBytes = marshalIpnsRecord(record);
              const recordBase64 = uint8ToBase64(recordBytes);

              await batchPublishIpnsRecords([
                {
                  ipnsName: ipnsKeypair.ipnsName,
                  recordBase64,
                  metadataCid,
                  recordType: 'file' as const,
                },
              ]);

              // Create FilePointer with owner-wrapped IPNS key
              const filePointer: FilePointer = {
                type: 'file',
                id: fileId,
                name: file.name,
                fileMetaIpnsName: ipnsKeypair.ipnsName,
                ipnsPrivateKeyEncrypted,
                createdAt: now,
                modifiedAt: now,
              };

              // Add file to folder metadata with conflict retry (C-01: read from refs)
              await withConflictRetry(
                async () => {
                  const freshChildren = [...folderChildrenRef.current, filePointer];
                  const seqNum = sequenceNumberRef.current ?? 0n;
                  const newSeq = await publishSharedFolderMetadata(
                    freshChildren,
                    currentFolderKey,
                    currentIpnsName,
                    currentIpnsKey,
                    seqNum
                  );
                  sequenceNumberRef.current = newSeq;
                  folderChildrenRef.current = freshChildren;
                  setCurrentSequenceNumber(newSeq);
                  setFolderChildren(freshChildren);
                },
                async () => {
                  await resyncSharedFolder();
                }
              );

              // Add share_keys for the recipient:
              // 1. File key (for reading/downloading)
              // 2. IPNS private key (for updating file content)
              // M-03: Non-fire-and-forget — show error if keys can't be saved
              const recipientWrappedFileKey = await wrapKey(fileKey, auth.vaultKeypair!.publicKey);
              try {
                await addShareKeys(currentShareId!, [
                  {
                    keyType: 'file',
                    itemId: fileId,
                    encryptedKey: bytesToHex(recipientWrappedFileKey),
                  },
                  {
                    keyType: 'file-ipns',
                    itemId: fileId,
                    encryptedKey: bytesToHex(recipientWrappedIpnsKey),
                  },
                ]);
                shareKeysCache.current.delete(currentShareId!);
              } catch (err) {
                console.warn('[share] Failed to add share_key for uploaded file:', err);
                setError('File uploaded but access keys could not be saved. Please re-upload.');
              }
            } finally {
              ipnsKeypair.privateKey.fill(0);
            }
          } finally {
            fileKey.fill(0);
          }
        });
      } catch (err) {
        const message = (err as Error).message || 'Upload failed';
        if (!message.includes('write access revoked')) {
          setError(message);
        }
        console.error('Shared folder upload failed:', err);
      } finally {
        setIsLoading(false);
      }
    },
    [
      folderKey,
      ipnsName,
      currentSequenceNumber,
      currentShareId,
      folderChildren,
      sharedItems,
      publishSharedFolderMetadata,
      resyncSharedFolder,
      withRevocationGuard,
    ]
  );

  /**
   * Create a subfolder in the currently-viewed write-shared folder.
   */
  const createFolderHandler = useCallback(
    async (name: string) => {
      const currentIpnsKey = ipnsPrivateKeyRef.current;
      const currentFolderKey = folderKey;
      const currentIpnsName = ipnsName;
      const seqNum = currentSequenceNumber;

      if (!currentIpnsKey || !currentFolderKey || !currentIpnsName || seqNum === null) {
        setError('Write access not available');
        return;
      }

      setIsLoading(true);
      setError(null);

      try {
        await withRevocationGuard(async () => {
          const {
            generateEd25519Keypair,
            deriveIpnsName,
            wrapKey: wrapSubfolderKey,
          } = await import('@cipherbox/crypto');

          // Generate new Ed25519 keypair for the subfolder
          const keypair = await generateEd25519Keypair();
          const subfolderIpnsName = await deriveIpnsName(keypair.publicKey);

          // Generate a random folder key for the subfolder
          const subfolderKey = generateRandomBytes(32);

          try {
            // Wrap subfolder keys with OWNER's key for FolderEntry
            const auth = useAuthStore.getState();
            if (!auth.vaultKeypair) throw new Error('No keypair available');

            const shareItem = sharedItems.find((s) => s.share.shareId === currentShareId);
            if (!shareItem) throw new Error('Share not found');
            const ownerPubKey = parsePublicKey(shareItem.share.sharerPublicKey);

            const wrappedFolderKey = await wrapSubfolderKey(subfolderKey, ownerPubKey);
            const wrappedIpnsKey = await wrapSubfolderKey(keypair.privateKey, ownerPubKey);

            // Create empty folder metadata and publish for the subfolder
            const subfolderMetadata: FolderMetadata = { version: 'v2', children: [] };
            const encryptedSubfolder = await encryptFolderMetadata(subfolderMetadata, subfolderKey);
            const subfolderBlob = new Blob([JSON.stringify(encryptedSubfolder)], {
              type: 'application/json',
            });
            const { cid: subfolderCid } = await addToIpfs(subfolderBlob);

            // Publish the subfolder's IPNS record
            await createAndPublishIpnsRecord({
              ipnsPrivateKey: keypair.privateKey,
              ipnsName: subfolderIpnsName,
              metadataCid: subfolderCid,
              sequenceNumber: 1n,
            });

            // Create a FolderEntry for the parent folder's metadata
            const folderId = crypto.randomUUID();
            const folderEntry: FolderEntry = {
              type: 'folder',
              id: folderId,
              name,
              ipnsName: subfolderIpnsName,
              ipnsPrivateKeyEncrypted: bytesToHex(wrappedIpnsKey),
              folderKeyEncrypted: bytesToHex(wrappedFolderKey),
              createdAt: Date.now(),
              modifiedAt: Date.now(),
            };

            // Add subfolder entry to parent folder with conflict retry
            await withConflictRetry(
              async () => {
                const freshChildren = [...folderChildrenRef.current, folderEntry];
                const seqNum = sequenceNumberRef.current ?? 0n;
                const newSeq = await publishSharedFolderMetadata(
                  freshChildren,
                  currentFolderKey,
                  currentIpnsName,
                  currentIpnsKey,
                  seqNum
                );
                sequenceNumberRef.current = newSeq;
                folderChildrenRef.current = freshChildren;
                setCurrentSequenceNumber(newSeq);
                setFolderChildren(freshChildren);
              },
              async () => {
                await resyncSharedFolder();
              }
            );

            // Add share_keys for the recipient so they can access the subfolder:
            // 1. folder key (for decrypting subfolder metadata)
            // 2. folder-ipns key (for signing subfolder IPNS publishes — enables writes at depth)
            const recipientWrappedFolderKey = await wrapSubfolderKey(
              subfolderKey,
              auth.vaultKeypair!.publicKey
            );
            const recipientWrappedIpnsKey = await wrapSubfolderKey(
              keypair.privateKey,
              auth.vaultKeypair!.publicKey
            );
            await addShareKeys(currentShareId!, [
              {
                keyType: 'folder',
                itemId: folderId,
                encryptedKey: bytesToHex(recipientWrappedFolderKey),
              },
              {
                keyType: 'folder-ipns',
                itemId: folderId,
                encryptedKey: bytesToHex(recipientWrappedIpnsKey),
              },
            ]);
            shareKeysCache.current.delete(currentShareId!);
          } finally {
            subfolderKey.fill(0);
            keypair.privateKey.fill(0);
          }
        });
      } catch (err) {
        const message = (err as Error).message || 'Failed to create folder';
        if (!message.includes('write access revoked')) {
          setError(message);
        }
        console.error('Shared folder create failed:', err);
      } finally {
        setIsLoading(false);
      }
    },
    [
      folderKey,
      ipnsName,
      currentSequenceNumber,
      currentShareId,
      folderChildren,
      sharedItems,
      publishSharedFolderMetadata,
      resyncSharedFolder,
      withRevocationGuard,
    ]
  );

  /**
   * Rename an item in the currently-viewed write-shared folder.
   */
  const renameItemHandler = useCallback(
    async (item: FolderChild, newName: string) => {
      const currentIpnsKey = ipnsPrivateKeyRef.current;
      const currentFolderKey = folderKey;
      const currentIpnsName = ipnsName;
      const seqNum = currentSequenceNumber;

      if (!currentIpnsKey || !currentFolderKey || !currentIpnsName || seqNum === null) {
        setError('Write access not available');
        return;
      }

      setIsLoading(true);
      setError(null);

      try {
        await withRevocationGuard(async () => {
          await withConflictRetry(
            async () => {
              // Update the item's name in folder metadata (C-01: read from refs)
              const updatedChildren = folderChildrenRef.current.map((child) =>
                child.id === item.id ? { ...child, name: newName, modifiedAt: Date.now() } : child
              );
              const seqNum = sequenceNumberRef.current ?? 0n;
              const newSeq = await publishSharedFolderMetadata(
                updatedChildren,
                currentFolderKey,
                currentIpnsName,
                currentIpnsKey,
                seqNum
              );
              sequenceNumberRef.current = newSeq;
              folderChildrenRef.current = updatedChildren;
              setCurrentSequenceNumber(newSeq);
              setFolderChildren(updatedChildren);
            },
            async () => {
              await resyncSharedFolder();
            }
          );
        });
      } catch (err) {
        const message = (err as Error).message || 'Failed to rename';
        if (!message.includes('write access revoked')) {
          setError(message);
        }
        console.error('Shared folder rename failed:', err);
      } finally {
        setIsLoading(false);
      }
    },
    [
      folderKey,
      ipnsName,
      currentSequenceNumber,
      folderChildren,
      publishSharedFolderMetadata,
      resyncSharedFolder,
      withRevocationGuard,
    ]
  );

  /**
   * Update a file's content in the currently-viewed write-shared folder.
   * Creates new encrypted content, updates the file's IPNS metadata record,
   * and refreshes the recipient's share_key.
   */
  const updateSharedFileHandler = useCallback(
    async (item: FilePointer, newContent: Uint8Array): Promise<void> => {
      const currentFolderKey = folderKey;

      if (!currentFolderKey) {
        throw new Error('Folder key not available');
      }

      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) {
        throw new Error('No keypair available');
      }

      // Get the owner's public key from the share record
      const shareItem = sharedItems.find((s) => s.share.shareId === currentShareId);
      if (!shareItem) {
        throw new Error('Share not found');
      }
      const ownerPublicKey = parsePublicKey(shareItem.share.sharerPublicKey);

      // 1. Encrypt new content with AES-256-GCM
      const { encryptAesGcm, generateFileKey, generateIv } = await import('@cipherbox/crypto');
      const fileKey = generateFileKey();
      const iv = generateIv();

      try {
        const ciphertext = await encryptAesGcm(newContent, fileKey, iv);

        // 2. Upload encrypted content to IPFS
        const fileBlob = new Blob([new Uint8Array(ciphertext)], {
          type: 'application/octet-stream',
        });
        const { cid: contentCid } = await addToIpfs(fileBlob);

        // 3. Wrap file key with owner's public key
        const ownerWrappedKey = await wrapKey(fileKey, ownerPublicKey);
        const fileKeyEncrypted = bytesToHex(ownerWrappedKey);

        // 4. Get the file's IPNS private key
        // For recipient-uploaded files: wrapped with recipient's key in share_keys (file-ipns)
        // For owner-uploaded files: wrapped with owner's key in FilePointer (try unwrap)
        const { updateFileMetadata } = await import('../services/file-metadata.service');

        let ipnsPrivKey: Uint8Array;
        const keys = await fetchShareKeys(currentShareId!);
        const ipnsKeyRecord = keys.find((k) => k.keyType === 'file-ipns' && k.itemId === item.id);

        if (ipnsKeyRecord) {
          // Recipient-uploaded file: unwrap from share_keys
          ipnsPrivKey = await unwrapKey(
            hexToBytes(ipnsKeyRecord.encryptedKey),
            auth.vaultKeypair.privateKey
          );
        } else if (item.ipnsPrivateKeyEncrypted) {
          // Owner-uploaded file: try unwrapping from FilePointer
          try {
            ipnsPrivKey = await unwrapKey(
              hexToBytes(item.ipnsPrivateKeyEncrypted),
              auth.vaultKeypair.privateKey
            );
          } catch {
            throw new Error('Cannot update: file IPNS key not accessible');
          }
        } else {
          throw new Error('Cannot update: no IPNS key available');
        }

        try {
          // 5. Resolve current file metadata and update
          const { resolveFileMetadata } = await import('../services/file-metadata.service');
          const { metadata: currentMeta } = await resolveFileMetadata(
            item.fileMetaIpnsName,
            currentFolderKey
          );

          const { ipnsRecord } = await updateFileMetadata({
            fileIpnsPrivateKey: ipnsPrivKey,
            fileMetaIpnsName: item.fileMetaIpnsName,
            folderKey: currentFolderKey,
            currentMetadata: currentMeta,
            updates: {
              cid: contentCid,
              fileKeyEncrypted,
              fileIv: bytesToHex(iv),
              size: newContent.length,
              encryptionMode: 'GCM',
            },
            createVersion: false,
          });

          // 6. Publish updated file IPNS record
          await batchPublishIpnsRecords([{ ...ipnsRecord, recordType: 'file' as const }]);

          // 7. Update share_key for recipient so they can re-read the file
          const recipientWrappedKey = await wrapKey(fileKey, auth.vaultKeypair!.publicKey);
          await addShareKeys(currentShareId!, [
            { keyType: 'file', itemId: item.id, encryptedKey: bytesToHex(recipientWrappedKey) },
          ])
            .then(() => {
              shareKeysCache.current.delete(currentShareId!);
            })
            .catch((err) => {
              console.warn('[share] Failed to update share_key after file edit:', err);
            });
        } finally {
          ipnsPrivKey.fill(0);
        }
      } finally {
        fileKey.fill(0);
      }
    },
    [folderKey, currentShareId, sharedItems]
  );

  /**
   * Delete an item from the currently-viewed write-shared folder.
   *
   * PoC limitation: Simply removes the item from folder metadata.
   * Full implementation would move to owner's recycle bin.
   */
  const deleteItemHandler = useCallback(
    async (item: FolderChild) => {
      const currentIpnsKey = ipnsPrivateKeyRef.current;
      const currentFolderKey = folderKey;
      const currentIpnsName = ipnsName;
      const seqNum = currentSequenceNumber;

      if (!currentIpnsKey || !currentFolderKey || !currentIpnsName || seqNum === null) {
        setError('Write access not available');
        return;
      }

      setIsLoading(true);
      setError(null);

      try {
        await withRevocationGuard(async () => {
          await withConflictRetry(
            async () => {
              // Remove item from folder metadata (C-01: read from refs)
              const updatedChildren = folderChildrenRef.current.filter(
                (child) => child.id !== item.id
              );
              const seqNum = sequenceNumberRef.current ?? 0n;
              const newSeq = await publishSharedFolderMetadata(
                updatedChildren,
                currentFolderKey,
                currentIpnsName,
                currentIpnsKey,
                seqNum
              );
              sequenceNumberRef.current = newSeq;
              folderChildrenRef.current = updatedChildren;
              setCurrentSequenceNumber(newSeq);
              setFolderChildren(updatedChildren);
            },
            async () => {
              await resyncSharedFolder();
            }
          );
        });
      } catch (err) {
        const message = (err as Error).message || 'Failed to delete';
        if (!message.includes('write access revoked')) {
          setError(message);
        }
        console.error('Shared folder delete failed:', err);
      } finally {
        setIsLoading(false);
      }
    },
    [
      folderKey,
      ipnsName,
      currentSequenceNumber,
      folderChildren,
      publishSharedFolderMetadata,
      resyncSharedFolder,
      withRevocationGuard,
    ]
  );

  // -------------------------------------------------------------------------
  // 30s sync polling for write shares
  // -------------------------------------------------------------------------

  useEffect(() => {
    // Only poll when viewing a write-shared folder
    if (currentView !== 'folder' || permission !== 'write' || !ipnsName || !folderKey) {
      clearPolling();
      return;
    }

    // Start 30s polling
    const currentIpnsName = ipnsName;
    const currentFolderKey = folderKey;

    pollIntervalRef.current = setInterval(async () => {
      try {
        // Re-fetch received shares from API to detect permission changes
        const freshShares = await fetchReceivedShares(100, 0);
        const currentShare = freshShares.shares.find((s) => s.shareId === currentShareId);

        // Check for silent revocation or permission downgrade
        if (!currentShare || currentShare.permission !== 'write') {
          useShareStore.getState().setReceivedShares(freshShares.shares);
          handleRevocation(false);
          clearPolling();
          return;
        }

        // Refresh folder contents
        await refreshFolderContents(currentIpnsName, currentFolderKey);
      } catch {
        // Silent failure during polling -- don't disrupt the UI
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
    refreshFolderContents,
  ]);

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
    navigateToShare,
    navigateToSubfolder,
    navigateUp,
    navigateToRoot,
    navigateToBreadcrumb,
    downloadSharedFile,
    hideSharedItem,
    uploadFile: uploadFileHandler,
    createFolder: createFolderHandler,
    renameItem: renameItemHandler,
    deleteItem: deleteItemHandler,
    updateSharedFile: updateSharedFileHandler,
  };
}
