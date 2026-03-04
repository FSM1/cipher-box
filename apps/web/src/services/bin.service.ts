/**
 * Bin Service - Recycle bin metadata IPNS lifecycle
 *
 * Manages the encrypted bin metadata: initialize on login, add entries on delete,
 * restore items, permanent delete (with CID unpin + quota update), empty bin,
 * and auto-purge expired entries.
 *
 * Follows the same IPFS/IPNS patterns as device-registry.service.ts.
 *
 * IMPORTANT: Bin operations must NEVER block login or the delete UI.
 * initializeBin is fire-and-forget; addToBin is fire-and-forget from the
 * delete flow. Errors are caught and logged, not thrown to callers.
 */

import {
  deriveBinIpnsKeypair,
  encryptBinMetadata,
  decryptBinMetadata,
  bytesToHex,
  hexToBytes,
  wrapKey,
  type RecycleBinMetadata,
  type BinEntry,
  type FolderChild,
  type FilePointer,
  type FolderEntry,
} from '@cipherbox/crypto';
import { addToIpfs, fetchFromIpfs, unpinFromIpfs } from '../lib/api/ipfs';
import { createAndPublishIpnsRecord, resolveIpnsRecord } from './ipns.service';
import { useAuthStore } from '../stores/auth.store';
import { useBinStore } from '../stores/bin.store';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useQuotaStore } from '../stores/quota.store';
import type { FolderNode } from '../stores/folder.store';

// Track whether TEE enrollment has been done for this session
let binTeeEnrolled = false;

// ---------------------------------------------------------------------------
// Internal helpers: load / save bin metadata
// ---------------------------------------------------------------------------

/**
 * Load and decrypt bin metadata from IPNS.
 *
 * @returns Decrypted metadata and IPNS resolution data, or null if no bin exists yet
 */
async function loadBinMetadata(params: { userPrivateKey: Uint8Array }): Promise<{
  metadata: RecycleBinMetadata;
  ipnsName: string;
  sequenceNumber: bigint;
} | null> {
  const binIpns = await deriveBinIpnsKeypair(params.userPrivateKey);
  const resolved = await resolveIpnsRecord(binIpns.ipnsName);

  if (!resolved) {
    return null;
  }

  const encryptedBytes = await fetchFromIpfs(resolved.cid);
  const metadata = await decryptBinMetadata(encryptedBytes, params.userPrivateKey);

  return {
    metadata,
    ipnsName: binIpns.ipnsName,
    sequenceNumber: resolved.sequenceNumber,
  };
}

/**
 * Encrypt and publish bin metadata to IPNS.
 *
 * Handles TEE enrollment on first write.
 */
async function saveBinMetadata(params: {
  metadata: RecycleBinMetadata;
  userPublicKey: Uint8Array;
  userPrivateKey: Uint8Array;
}): Promise<void> {
  const binIpns = await deriveBinIpnsKeypair(params.userPrivateKey);

  // Encrypt metadata with user's public key (ECIES)
  const encryptedBytes = await encryptBinMetadata(params.metadata, params.userPublicKey);

  // Pin to IPFS
  const { cid } = await addToIpfs(new Blob([encryptedBytes as BlobPart]));

  // TEE enrollment on first write (fire-and-forget)
  let encryptedIpnsKey: string | undefined;
  let keyEpoch: number | undefined;

  if (!binTeeEnrolled) {
    const teeKeys = useAuthStore.getState().teeKeys;
    if (teeKeys?.currentPublicKey) {
      try {
        const wrappedKey = await wrapKey(binIpns.privateKey, hexToBytes(teeKeys.currentPublicKey));
        encryptedIpnsKey = bytesToHex(wrappedKey);
        keyEpoch = teeKeys.currentEpoch;
        binTeeEnrolled = true;
      } catch (err) {
        console.error('[Bin] TEE enrollment failed (non-blocking):', err);
      }
    }
  }

  // Publish IPNS record
  await createAndPublishIpnsRecord({
    ipnsPrivateKey: binIpns.privateKey,
    ipnsName: binIpns.ipnsName,
    metadataCid: cid,
    sequenceNumber: BigInt(params.metadata.sequenceNumber),
    encryptedIpnsPrivateKey: encryptedIpnsKey,
    keyEpoch,
  });
}

// ---------------------------------------------------------------------------
// Public API: initializeBin
// ---------------------------------------------------------------------------

/**
 * Initialize or load the recycle bin on login.
 *
 * Derives the deterministic IPNS keypair, resolves existing bin metadata
 * from IPNS (or creates empty state), and populates the bin store.
 *
 * Non-blocking: errors are logged, not thrown.
 */
export async function initializeBin(params: {
  userPrivateKey: Uint8Array;
  userPublicKey: Uint8Array;
}): Promise<void> {
  const store = useBinStore.getState();
  store.setLoading(true);

  try {
    // Reset TEE enrollment tracking for new session
    binTeeEnrolled = false;

    const binIpns = await deriveBinIpnsKeypair(params.userPrivateKey);
    store.setBinIpnsName(binIpns.ipnsName);

    // Try to load existing bin metadata
    const loaded = await loadBinMetadata({ userPrivateKey: params.userPrivateKey });

    if (loaded) {
      store.setEntries(loaded.metadata.entries, loaded.metadata.sequenceNumber);
    } else {
      // No bin exists yet -- initialize with empty state
      store.setEntries([], 0);
    }
  } catch (error) {
    console.error('[Bin] Failed to initialize bin:', error);
    store.setError(error instanceof Error ? error.message : 'Failed to initialize bin');
    store.setLoading(false);
  }
}

// ---------------------------------------------------------------------------
// Public API: addToBin
// ---------------------------------------------------------------------------

/**
 * Add a deleted item to the recycle bin.
 *
 * Creates a BinEntry from the FolderChild that was removed from its parent,
 * appends it to the bin metadata, encrypts, and publishes.
 *
 * @param params.item - The FolderChild (FilePointer or FolderEntry) that was removed
 * @param params.parentIpnsName - IPNS name of the original parent folder
 * @param params.parentPath - Breadcrumb path at deletion time (e.g., "My Vault / Documents")
 * @param params.userPublicKey - User's secp256k1 public key for ECIES encryption
 * @param params.userPrivateKey - User's secp256k1 private key for IPNS derivation
 */
export async function addToBin(params: {
  item: FolderChild;
  parentIpnsName: string;
  parentPath: string;
  userPublicKey: Uint8Array;
  userPrivateKey: Uint8Array;
}): Promise<void> {
  const { item, parentIpnsName, parentPath, userPublicKey, userPrivateKey } = params;

  // Build bin entry
  const isFile = item.type === 'file';
  const entry: BinEntry = {
    id: crypto.randomUUID(),
    itemType: isFile ? 'file' : 'folder',
    name: item.name,
    originalParentIpnsName: parentIpnsName,
    originalPath: parentPath,
    deletedAt: Date.now(),
    size: 0, // Files: resolved lazily on permanent delete. Folders: 0.
    mimeType: '',
    filePointer: isFile ? (item as FilePointer) : undefined,
    folderEntry: !isFile ? (item as FolderEntry) : undefined,
  };

  // Read current bin state and build updated metadata
  const store = useBinStore.getState();
  const currentEntries = [...store.entries, entry];
  const newSeq = store.sequenceNumber + 1;

  const metadata: RecycleBinMetadata = {
    version: 'v1',
    sequenceNumber: newSeq,
    entries: currentEntries,
  };

  // Encrypt and publish
  await saveBinMetadata({ metadata, userPublicKey, userPrivateKey });

  // Update local store
  store.addEntry(entry);
}

// ---------------------------------------------------------------------------
// Public API: restoreFromBin
// ---------------------------------------------------------------------------

/**
 * Restore a bin entry to its original folder.
 *
 * Looks up the target folder by IPNS name. If found, re-adds the preserved
 * FolderChild. Handles name collisions (appends " (restored)"). If original
 * parent is also in the bin, attempts recursive parent restore (max depth 5).
 * Falls back to root folder if parent is gone.
 */
export async function restoreFromBin(params: {
  entryId: string;
  userPublicKey: Uint8Array;
  userPrivateKey: Uint8Array;
}): Promise<void> {
  const { entryId, userPublicKey, userPrivateKey } = params;

  const binStore = useBinStore.getState();
  const entry = binStore.entries.find((e) => e.id === entryId);
  if (!entry) throw new Error('Bin entry not found');

  // Resolve original parent folder
  const targetFolder = await resolveTargetFolder(entry.originalParentIpnsName, 0, {
    userPublicKey,
    userPrivateKey,
  });

  // Get the FolderChild to restore
  const child = getRestoredChild(entry);

  // Check for name collisions in target folder and rename if needed
  const finalChild = resolveNameCollision(child, targetFolder.children);

  // Add child back to target folder
  const { updateFolderMetadata } = await import('./folder.service');
  const updatedChildren = [...targetFolder.children, finalChild];
  const { newSequenceNumber } = await updateFolderMetadata({
    folderId: targetFolder.id,
    children: updatedChildren,
    folderKey: targetFolder.folderKey,
    ipnsPrivateKey: targetFolder.ipnsPrivateKey,
    ipnsName: targetFolder.ipnsName,
    sequenceNumber: targetFolder.sequenceNumber,
  });

  // Update folder store
  const folderStore = useFolderStore.getState();
  folderStore.updateFolderChildren(targetFolder.id, updatedChildren);
  folderStore.updateFolderSequence(targetFolder.id, newSequenceNumber);

  // If restoring a folder, re-add the folder node to the store
  if (entry.itemType === 'folder' && entry.folderEntry) {
    const existingNode = folderStore.folders[entry.folderEntry.id];
    if (!existingNode) {
      // Create a placeholder node -- it will be fully loaded on next navigation
      folderStore.setFolder({
        id: entry.folderEntry.id,
        name: finalChild.name,
        ipnsName: entry.folderEntry.ipnsName,
        parentId: targetFolder.id,
        children: [],
        isLoaded: false,
        isLoading: false,
        sequenceNumber: 0n,
        // These will be populated when the folder is loaded
        folderKey: new Uint8Array(32),
        ipnsPrivateKey: new Uint8Array(64),
      });
    }
  }

  // Remove entry from bin metadata and publish
  await removeEntriesFromBin([entryId], { userPublicKey, userPrivateKey });
}

// ---------------------------------------------------------------------------
// Public API: permanentlyDelete
// ---------------------------------------------------------------------------

/**
 * Permanently delete a bin entry: unpin CIDs and update quota.
 *
 * For files: resolves file IPNS -> gets CID -> unpins.
 * For folders: recursively resolves all descendant file CIDs -> unpins all.
 */
export async function permanentlyDelete(params: {
  entryId: string;
  userPublicKey: Uint8Array;
  userPrivateKey: Uint8Array;
}): Promise<void> {
  const { entryId, userPublicKey, userPrivateKey } = params;

  const binStore = useBinStore.getState();
  const entry = binStore.entries.find((e) => e.id === entryId);
  if (!entry) throw new Error('Bin entry not found');

  // Perform CID cleanup
  await cleanupEntryCids(entry);

  // Remove from bin metadata and publish
  await removeEntriesFromBin([entryId], { userPublicKey, userPrivateKey });
}

// ---------------------------------------------------------------------------
// Public API: emptyBin
// ---------------------------------------------------------------------------

/**
 * Permanently delete all bin entries.
 *
 * Processes each entry's CID cleanup, then publishes empty bin metadata.
 */
export async function emptyBin(params: {
  userPublicKey: Uint8Array;
  userPrivateKey: Uint8Array;
}): Promise<void> {
  const { userPublicKey, userPrivateKey } = params;

  const binStore = useBinStore.getState();
  const entries = [...binStore.entries];

  // Cleanup CIDs for all entries (best-effort, continue on individual failures)
  for (const entry of entries) {
    try {
      await cleanupEntryCids(entry);
    } catch (err) {
      console.error(`[Bin] Failed to cleanup CIDs for ${entry.name}:`, err);
    }
  }

  // Publish empty bin metadata
  const newSeq = binStore.sequenceNumber + 1;
  const metadata: RecycleBinMetadata = {
    version: 'v1',
    sequenceNumber: newSeq,
    entries: [],
  };

  await saveBinMetadata({ metadata, userPublicKey, userPrivateKey });

  // Update local store
  binStore.setEntries([], newSeq);
}

// ---------------------------------------------------------------------------
// Public API: purgeExpired
// ---------------------------------------------------------------------------

/**
 * Purge expired bin entries based on retention period.
 *
 * Filters entries past their retention, cleans up CIDs, and publishes
 * updated bin metadata in a single IPNS publish.
 */
export async function purgeExpired(params: {
  retentionDays: number;
  userPublicKey: Uint8Array;
  userPrivateKey: Uint8Array;
}): Promise<void> {
  const { retentionDays, userPublicKey, userPrivateKey } = params;

  const binStore = useBinStore.getState();
  const retentionMs = retentionDays * 24 * 60 * 60 * 1000;
  const now = Date.now();

  const expired = binStore.entries.filter((e) => now - e.deletedAt > retentionMs);
  if (expired.length === 0) return;

  console.log(`[Bin] Purging ${expired.length} expired entries`);

  // Cleanup CIDs for expired entries (best-effort)
  for (const entry of expired) {
    try {
      await cleanupEntryCids(entry);
    } catch (err) {
      console.error(`[Bin] Failed to cleanup CIDs for expired ${entry.name}:`, err);
    }
  }

  // Remove expired entries and publish
  const expiredIds = expired.map((e) => e.id);
  await removeEntriesFromBin(expiredIds, { userPublicKey, userPrivateKey });
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Remove entries from bin metadata and publish the updated metadata.
 */
async function removeEntriesFromBin(
  entryIds: string[],
  params: { userPublicKey: Uint8Array; userPrivateKey: Uint8Array }
): Promise<void> {
  const binStore = useBinStore.getState();
  const idsToRemove = new Set(entryIds);
  const remainingEntries = binStore.entries.filter((e) => !idsToRemove.has(e.id));
  const newSeq = binStore.sequenceNumber + 1;

  const metadata: RecycleBinMetadata = {
    version: 'v1',
    sequenceNumber: newSeq,
    entries: remainingEntries,
  };

  await saveBinMetadata({
    metadata,
    userPublicKey: params.userPublicKey,
    userPrivateKey: params.userPrivateKey,
  });

  // Update local store
  binStore.removeEntries(entryIds);
}

/**
 * Cleanup CIDs for a bin entry (unpin from IPFS + update quota).
 *
 * Files: resolve file IPNS -> get CID -> unpin
 * Folders: recursively resolve descendant file CIDs -> unpin all
 */
async function cleanupEntryCids(entry: BinEntry): Promise<void> {
  if (entry.itemType === 'file' && entry.filePointer) {
    const fileIpnsName = entry.filePointer.fileMetaIpnsName;
    if (fileIpnsName) {
      try {
        const resolved = await resolveIpnsRecord(fileIpnsName);
        if (resolved?.cid) {
          // Fetch file metadata to get the actual content CID and size
          const metaBytes = await fetchFromIpfs(resolved.cid);
          const metaJson = new TextDecoder().decode(metaBytes);
          const fileMeta = JSON.parse(metaJson);

          // Unpin the content CID (encrypted file data)
          if (fileMeta.cid) {
            await unpinFromIpfs(fileMeta.cid);
            // Update quota
            if (fileMeta.size && typeof fileMeta.size === 'number') {
              useQuotaStore.getState().removeUsage(fileMeta.size);
            }
          }

          // Also unpin the metadata CID
          await unpinFromIpfs(resolved.cid).catch(() => {});
        }
      } catch (err) {
        console.error(`[Bin] CID cleanup failed for file ${entry.name}:`, err);
      }
    }
  } else if (entry.itemType === 'folder' && entry.folderEntry) {
    // Recursively resolve folder to find all descendant file CIDs
    await cleanupFolderCids(entry.folderEntry.ipnsName);
  }
}

/**
 * Recursively unpin all CIDs in a folder tree.
 */
async function cleanupFolderCids(folderIpnsName: string): Promise<void> {
  try {
    const resolved = await resolveIpnsRecord(folderIpnsName);
    if (!resolved?.cid) return;

    // Try to load folder metadata -- it may be AES-GCM encrypted
    // We don't have the folder key here, so we check if the folder is
    // loaded in the store first
    const folders = useFolderStore.getState().folders;
    const folderNode = Object.values(folders).find((f) => f.ipnsName === folderIpnsName);

    if (folderNode) {
      // Folder is loaded -- iterate children
      for (const child of folderNode.children) {
        if (child.type === 'file') {
          const fp = child as FilePointer;
          if (fp.fileMetaIpnsName) {
            try {
              const fileResolved = await resolveIpnsRecord(fp.fileMetaIpnsName);
              if (fileResolved?.cid) {
                const metaBytes = await fetchFromIpfs(fileResolved.cid);
                const metaJson = new TextDecoder().decode(metaBytes);
                const fileMeta = JSON.parse(metaJson);
                if (fileMeta.cid) {
                  await unpinFromIpfs(fileMeta.cid);
                  if (fileMeta.size && typeof fileMeta.size === 'number') {
                    useQuotaStore.getState().removeUsage(fileMeta.size);
                  }
                }
                await unpinFromIpfs(fileResolved.cid).catch(() => {});
              }
            } catch (err) {
              console.error(`[Bin] CID cleanup failed for nested file:`, err);
            }
          }
        } else if (child.type === 'folder') {
          const fe = child as FolderEntry;
          await cleanupFolderCids(fe.ipnsName);
        }
      }
    }

    // Unpin the folder metadata CID itself
    await unpinFromIpfs(resolved.cid).catch(() => {});
  } catch (err) {
    console.error(`[Bin] Folder CID cleanup failed for ${folderIpnsName}:`, err);
  }
}

/**
 * Resolve the target folder for a restore operation.
 *
 * Walks the folder store to find a folder with the given IPNS name.
 * If not found, checks if the parent is in the bin (recursive restore).
 * Falls back to root folder.
 */
async function resolveTargetFolder(
  parentIpnsName: string,
  depth: number,
  params: { userPublicKey: Uint8Array; userPrivateKey: Uint8Array }
): Promise<FolderNode> {
  // Max recursion depth to prevent infinite loops
  if (depth > 5) {
    console.warn('[Bin] Max restore depth reached, falling back to root');
    return getRootFolder();
  }

  // Look up folder by IPNS name in folder store
  const folders = useFolderStore.getState().folders;
  const targetFolder = Object.values(folders).find((f) => f.ipnsName === parentIpnsName);

  if (targetFolder) {
    return targetFolder;
  }

  // Check if parent is in the bin
  const binStore = useBinStore.getState();
  const parentBinEntry = binStore.entries.find(
    (e) => e.itemType === 'folder' && e.folderEntry && e.folderEntry.ipnsName === parentIpnsName
  );

  if (parentBinEntry) {
    // Restore parent first (recursive)
    console.log(`[Bin] Restoring parent folder "${parentBinEntry.name}" first`);
    await restoreFromBin({
      entryId: parentBinEntry.id,
      userPublicKey: params.userPublicKey,
      userPrivateKey: params.userPrivateKey,
    });

    // After restoring parent, try to find it again
    const updatedFolders = useFolderStore.getState().folders;
    const restoredParent = Object.values(updatedFolders).find((f) => f.ipnsName === parentIpnsName);
    if (restoredParent) {
      return restoredParent;
    }
  }

  // Parent truly gone -- restore to root
  console.warn(`[Bin] Original parent not found (${parentIpnsName}), restoring to root`);
  return getRootFolder();
}

/**
 * Get the root folder from the folder store.
 */
function getRootFolder(): FolderNode {
  const folders = useFolderStore.getState().folders;
  const root = folders['root'];
  if (root) return root;

  // Fallback: construct from vault store
  const vault = useVaultStore.getState();
  if (!vault.rootFolderKey || !vault.rootIpnsKeypair || !vault.rootIpnsName) {
    throw new Error('Vault not initialized - cannot restore to root');
  }

  return {
    id: 'root',
    name: 'My Vault',
    ipnsName: vault.rootIpnsName,
    parentId: null,
    children: folders['root']?.children ?? [],
    isLoaded: true,
    isLoading: false,
    sequenceNumber: 0n,
    folderKey: vault.rootFolderKey,
    ipnsPrivateKey: vault.rootIpnsKeypair.privateKey,
  };
}

/**
 * Get the FolderChild to restore from a bin entry.
 */
function getRestoredChild(entry: BinEntry): FolderChild {
  if (entry.itemType === 'file' && entry.filePointer) {
    return { ...entry.filePointer, modifiedAt: Date.now() };
  } else if (entry.itemType === 'folder' && entry.folderEntry) {
    return { ...entry.folderEntry, modifiedAt: Date.now() };
  }
  throw new Error(`Bin entry ${entry.id} has no stored item reference`);
}

/**
 * Check for name collisions and rename if needed.
 */
function resolveNameCollision(child: FolderChild, existingChildren: FolderChild[]): FolderChild {
  const existingNames = new Set(existingChildren.map((c) => c.name));
  if (!existingNames.has(child.name)) {
    return child;
  }

  // Append " (restored)" suffix, incrementing if needed
  let newName = `${child.name} (restored)`;
  let counter = 2;
  while (existingNames.has(newName)) {
    newName = `${child.name} (restored ${counter})`;
    counter++;
  }

  return { ...child, name: newName };
}
