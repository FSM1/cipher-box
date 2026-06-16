/**
 * @cipherbox/sdk - Bin operations
 *
 * Extracted from: apps/web/src/services/bin.service.ts (962 LOC)
 * All Zustand store access replaced with explicit parameters.
 *
 * Bin operations manage the recycle bin lifecycle:
 * - addToBin: soft-delete (remove from folder, add to bin)
 * - restoreFromBin: undo soft-delete (remove from bin, add back to folder)
 * - permanentDeleteFromBin: hard-delete with CID cleanup
 * - emptyBin: permanently delete all bin entries
 * - loadBin: load current bin metadata from IPNS
 *
 * Each function takes explicit params instead of reading from stores.
 */

import type { SdkContext, TeeKeys } from '@cipherbox/sdk-core';
import * as sdkCore from '@cipherbox/sdk-core';
import {
  encryptBinMetadata,
  decryptBinMetadata,
  deriveBinIpnsKeypair,
  type BinEntry,
  type RecycleBinMetadata,
  type FolderChild,
  type FilePointer,
  type FolderEntry,
} from '@cipherbox/core';
import { bytesToHex, hexToBytes, wrapKey } from '@cipherbox/crypto';
import type { FolderTree } from '../state/folder-tree';

/** Current bin metadata version. */
const BIN_METADATA_VERSION = 'v1' as const;

/**
 * Context for bin operations. Replaces Zustand store access.
 */
export type BinOperationContext = {
  ctx: SdkContext;
  userPrivateKey: Uint8Array;
  userPublicKey: Uint8Array;
  rootFolderKey: Uint8Array;
  teeKeys?: TeeKeys;
};

/**
 * Internal state for the bin (replaces useBinStore).
 */
export type BinState = {
  entries: BinEntry[];
  sequenceNumber: number;
  ipnsName: string;
};

// ---------------------------------------------------------------------------
// Internal helpers: load / save bin metadata
// ---------------------------------------------------------------------------

/**
 * Load and decrypt bin metadata from IPNS.
 */
async function loadBinMetadataInternal(params: {
  userPrivateKey: Uint8Array;
  ctx: SdkContext;
}): Promise<{
  metadata: RecycleBinMetadata;
  ipnsName: string;
  sequenceNumber: bigint;
} | null> {
  const binIpns = await deriveBinIpnsKeypair(params.userPrivateKey);
  const resolved = await sdkCore.resolveIpnsRecord(binIpns.ipnsName, params.ctx);

  if (!resolved) return null;

  const encryptedBytes = await sdkCore.fetchFromIpfs(params.ctx, resolved.cid);
  const metadata = await decryptBinMetadata(encryptedBytes, params.userPrivateKey);

  return {
    metadata,
    ipnsName: binIpns.ipnsName,
    sequenceNumber: resolved.sequenceNumber,
  };
}

/**
 * Encrypt and publish bin metadata to IPNS.
 */
async function saveBinMetadata(params: {
  metadata: RecycleBinMetadata;
  binCtx: BinOperationContext;
}): Promise<void> {
  const binIpns = await deriveBinIpnsKeypair(params.binCtx.userPrivateKey);

  // Encrypt metadata with user's public key (ECIES)
  const encryptedBytes = await encryptBinMetadata(params.metadata, params.binCtx.userPublicKey);

  // Pin to IPFS
  const { cid } = await sdkCore.addToIpfs(params.binCtx.ctx, encryptedBytes);

  // TEE enrollment (optional)
  let encryptedIpnsKey: string | undefined;
  let keyEpoch: number | undefined;

  if (params.binCtx.teeKeys?.currentPublicKey) {
    try {
      const teePublicKey = hexToBytes(params.binCtx.teeKeys.currentPublicKey);
      const wrappedKey = await wrapKey(binIpns.privateKey, teePublicKey);
      encryptedIpnsKey = bytesToHex(wrappedKey);
      keyEpoch = params.binCtx.teeKeys.currentEpoch;
    } catch {
      // TEE enrollment failure is non-blocking
    }
  }

  // Publish IPNS record with verification
  await publishWithVerify({
    ipnsName: binIpns.ipnsName,
    ipnsPrivateKey: binIpns.privateKey,
    cid,
    sequenceNumber: BigInt(params.metadata.sequenceNumber),
    encryptedIpnsPrivateKey: encryptedIpnsKey,
    keyEpoch,
    ctx: params.binCtx.ctx,
  });
}

/**
 * Publish an IPNS record and verify it is resolvable.
 *
 * Wraps createAndPublishIpnsRecord with a resolve-back verification loop.
 * On verify failure, retries with exponential backoff (500ms, 1000ms, 2000ms).
 * After all retries exhausted, does NOT throw -- the publish went through,
 * verification just couldn't confirm propagation.
 */
async function publishWithVerify(params: {
  ipnsName: string;
  ipnsPrivateKey: Uint8Array;
  cid: string;
  sequenceNumber: bigint;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
  ctx: SdkContext;
  maxRetries?: number;
}): Promise<void> {
  const maxRetries = params.maxRetries ?? 3;
  // Publish once -- the API call is idempotent but no need to repeat it
  await sdkCore.createAndPublishIpnsRecord({
    ipnsPrivateKey: params.ipnsPrivateKey,
    ipnsName: params.ipnsName,
    metadataCid: params.cid,
    sequenceNumber: params.sequenceNumber,
    encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
    keyEpoch: params.keyEpoch,
    ctx: params.ctx,
  });
  // Verify with retries: resolve back to confirm DB cache was written
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const resolved = await sdkCore.resolveIpnsRecord(params.ipnsName, params.ctx);
    if (resolved) return;
    if (attempt < maxRetries - 1) {
      await new Promise((r) => setTimeout(r, 500 * Math.pow(2, attempt)));
    }
  }
  // After all retries, don't throw -- the publish went through, just verification failed.
  // The record may still propagate eventually.
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Load the recycle bin metadata from IPNS.
 *
 * If no bin IPNS record exists yet (first login / never deleted anything),
 * returns an empty BinState so that deleteToBin can create the first record.
 * The old bin service handled this by creating in-memory-only empty state;
 * the SDK must do the same to avoid "Bin not loaded" errors on first delete.
 *
 * @returns Current bin state (never null — empty state if no record exists)
 */
export async function loadBin(params: { binCtx: BinOperationContext }): Promise<BinState> {
  const loaded = await loadBinMetadataInternal({
    userPrivateKey: params.binCtx.userPrivateKey,
    ctx: params.binCtx.ctx,
  });

  if (!loaded) {
    // No bin IPNS record resolved. A null is NOT a reliable "bin is empty"
    // signal: resolveIpnsRecord also returns null on a cold-cache miss right
    // after a page reload, or while a concurrent loadBin()/delete is mid-flight.
    // Auto-repairing on a false null is destructive — the bin publish path uses
    // no expectedSequenceNumber, so the API increments and overwrites the real
    // record's CID with the empty-bin CID (apps/api ipns.service upsertFolderIpns),
    // wiping every entry. So re-resolve once before assuming the bin is new.
    const recheck = await loadBinMetadataInternal({
      userPrivateKey: params.binCtx.userPrivateKey,
      ctx: params.binCtx.ctx,
    });
    if (recheck) {
      return {
        entries: recheck.metadata.entries,
        sequenceNumber: recheck.metadata.sequenceNumber,
        ipnsName: recheck.ipnsName,
      };
    }

    // Still nothing on the second resolve — treat as a genuinely new bin and
    // auto-repair by publishing an empty record to establish the IPNS sequence.
    console.warn('[CipherBox] Bin IPNS record not found — auto-repairing with empty bin');
    const binIpns = await deriveBinIpnsKeypair(params.binCtx.userPrivateKey);
    const emptyMetadata: RecycleBinMetadata = {
      version: BIN_METADATA_VERSION,
      sequenceNumber: 1,
      entries: [],
    };
    // Publish empty bin to establish the IPNS record (with retry/verify)
    await saveBinMetadata({ metadata: emptyMetadata, binCtx: params.binCtx });

    // Re-resolve after publishing. If a real (non-empty / higher-sequence) record
    // surfaces now — because a concurrent delete landed, or the empty publish was
    // rejected/superseded — adopt it instead of returning the empty state we just
    // wrote, so the bin never appears spuriously empty.
    const afterPublish = await loadBinMetadataInternal({
      userPrivateKey: params.binCtx.userPrivateKey,
      ctx: params.binCtx.ctx,
    });
    if (afterPublish && afterPublish.metadata.sequenceNumber > 1) {
      return {
        entries: afterPublish.metadata.entries,
        sequenceNumber: afterPublish.metadata.sequenceNumber,
        ipnsName: afterPublish.ipnsName,
      };
    }

    return {
      entries: [],
      sequenceNumber: 1,
      ipnsName: binIpns.ipnsName,
    };
  }

  return {
    entries: loaded.metadata.entries,
    sequenceNumber: loaded.metadata.sequenceNumber,
    ipnsName: loaded.ipnsName,
  };
}

/**
 * Add item to recycle bin.
 *
 * Removes the item from the folder metadata (via deleteFromFolder),
 * creates a BinEntry, appends to bin metadata, and publishes both.
 *
 * @returns The removed item from the folder
 */
export async function addToBin(params: {
  folderIpnsName: string;
  childId: string;
  parentPath: string;
  folderTree: FolderTree;
  binState: BinState;
  binCtx: BinOperationContext;
}): Promise<{ removedItem: FolderChild; updatedBinState: BinState }> {
  const folder = params.folderTree.get(params.folderIpnsName);
  if (!folder) throw new Error('Folder not loaded');

  // 1. Remove item from folder metadata
  const baseChildren = [...folder.children];
  const { updatedChildren, removedItem } = sdkCore.deleteFromFolder({
    children: folder.children,
    childId: params.childId,
  });

  // 2. Publish updated folder metadata
  const { newSequenceNumber, publishedChildren } = await sdkCore.updateFolderMetadataAndPublish({
    children: updatedChildren,
    baseChildren,
    folderKey: folder.folderKey,
    ipnsPrivateKey: folder.ipnsKeypair.privateKey,
    ipnsName: params.folderIpnsName,
    sequenceNumber: folder.sequenceNumber,
    ctx: params.binCtx.ctx,
  });

  // 3. Update folder state — adopt merged published set (CR-01)
  folder.children = publishedChildren;
  folder.sequenceNumber = newSequenceNumber;
  folder.lastLoadedAt = Date.now();
  params.folderTree.set(params.folderIpnsName, folder);

  // 4. Build bin entry
  const isFile = removedItem.type === 'file';
  const entry: BinEntry = {
    id: crypto.randomUUID(),
    itemType: isFile ? 'file' : 'folder',
    name: removedItem.name,
    originalParentIpnsName: params.folderIpnsName,
    originalPath: params.parentPath,
    deletedAt: Date.now(),
    size: 0,
    mimeType: '',
    filePointer: isFile ? (removedItem as FilePointer) : undefined,
    folderEntry: !isFile ? (removedItem as FolderEntry) : undefined,
  };

  // 5. Update bin metadata and publish
  const updatedEntries = [...params.binState.entries, entry];
  const newBinSeq = params.binState.sequenceNumber + 1;

  const metadata: RecycleBinMetadata = {
    version: BIN_METADATA_VERSION,
    sequenceNumber: newBinSeq,
    entries: updatedEntries,
  };

  await saveBinMetadata({ metadata, binCtx: params.binCtx });

  const updatedBinState: BinState = {
    entries: updatedEntries,
    sequenceNumber: newBinSeq,
    ipnsName: params.binState.ipnsName,
  };

  return { removedItem, updatedBinState };
}

/**
 * Restore an item from the recycle bin back to a folder.
 *
 * Removes the entry from bin metadata, adds the preserved FolderChild
 * back to the target folder's children, and publishes both.
 */
export async function restoreFromBin(params: {
  entryId: string;
  targetFolderIpnsName: string;
  folderTree: FolderTree;
  binState: BinState;
  binCtx: BinOperationContext;
}): Promise<{ restoredItem: FolderChild; updatedBinState: BinState }> {
  // 1. Find the bin entry
  const entry = params.binState.entries.find((e) => e.id === params.entryId);
  if (!entry) throw new Error('Bin entry not found');

  // 2. Get the FolderChild to restore
  let child: FolderChild;
  if (entry.itemType === 'file' && entry.filePointer) {
    child = { ...entry.filePointer, modifiedAt: Date.now() };
  } else if (entry.itemType === 'folder' && entry.folderEntry) {
    child = { ...entry.folderEntry, modifiedAt: Date.now() };
  } else {
    throw new Error('Bin entry has no stored item reference');
  }

  // 3. Add child back to target folder
  const targetFolder = params.folderTree.get(params.targetFolderIpnsName);
  if (!targetFolder) throw new Error('Target folder not loaded');

  // Handle name collisions
  const existingNames = new Set(targetFolder.children.map((c) => c.name));
  if (existingNames.has(child.name)) {
    let newName = `${child.name} (restored)`;
    let counter = 2;
    while (existingNames.has(newName)) {
      newName = `${child.name} (restored ${counter})`;
      counter++;
    }
    child = { ...child, name: newName };
  }

  const baseChildren = [...targetFolder.children];
  const updatedFolderChildren = [...targetFolder.children, child];

  // 4. Publish updated folder metadata
  const { newSequenceNumber, publishedChildren } = await sdkCore.updateFolderMetadataAndPublish({
    children: updatedFolderChildren,
    baseChildren,
    folderKey: targetFolder.folderKey,
    ipnsPrivateKey: targetFolder.ipnsKeypair.privateKey,
    ipnsName: params.targetFolderIpnsName,
    sequenceNumber: targetFolder.sequenceNumber,
    ctx: params.binCtx.ctx,
  });

  // 5. Update folder state — adopt merged published set (CR-01)
  targetFolder.children = publishedChildren;
  targetFolder.sequenceNumber = newSequenceNumber;
  targetFolder.lastLoadedAt = Date.now();
  params.folderTree.set(params.targetFolderIpnsName, targetFolder);

  // 6. Remove entry from bin and publish
  const remainingEntries = params.binState.entries.filter((e) => e.id !== params.entryId);
  const newBinSeq = params.binState.sequenceNumber + 1;

  const metadata: RecycleBinMetadata = {
    version: BIN_METADATA_VERSION,
    sequenceNumber: newBinSeq,
    entries: remainingEntries,
  };

  await saveBinMetadata({ metadata, binCtx: params.binCtx });

  const updatedBinState: BinState = {
    entries: remainingEntries,
    sequenceNumber: newBinSeq,
    ipnsName: params.binState.ipnsName,
  };

  return { restoredItem: child, updatedBinState };
}

/**
 * Permanently delete a bin entry (unpin CIDs, remove from bin metadata).
 *
 * For files: unpins the content CID if available.
 * Does NOT handle recursive folder cleanup (that requires deep IPNS traversal).
 */
export async function permanentDeleteFromBin(params: {
  entryId: string;
  binState: BinState;
  binCtx: BinOperationContext;
}): Promise<{ updatedBinState: BinState }> {
  const entry = params.binState.entries.find((e) => e.id === params.entryId);
  if (!entry) throw new Error('Bin entry not found');

  // Unpin content CID if available (best-effort)
  if (entry.contentCid) {
    try {
      await sdkCore.unpinFromIpfs(params.binCtx.ctx, entry.contentCid);
    } catch {
      // Best-effort CID cleanup
    }
  }

  // Remove from bin metadata and publish
  const remainingEntries = params.binState.entries.filter((e) => e.id !== params.entryId);
  const newBinSeq = params.binState.sequenceNumber + 1;

  const metadata: RecycleBinMetadata = {
    version: BIN_METADATA_VERSION,
    sequenceNumber: newBinSeq,
    entries: remainingEntries,
  };

  await saveBinMetadata({ metadata, binCtx: params.binCtx });

  return {
    updatedBinState: {
      entries: remainingEntries,
      sequenceNumber: newBinSeq,
      ipnsName: params.binState.ipnsName,
    },
  };
}

/**
 * Empty the bin by permanently deleting all entries.
 *
 * Cleans up CIDs (best-effort) and publishes empty bin metadata.
 */
export async function emptyBin(params: {
  binState: BinState;
  binCtx: BinOperationContext;
}): Promise<{ updatedBinState: BinState }> {
  // Best-effort CID cleanup for each entry
  for (const entry of params.binState.entries) {
    if (entry.contentCid) {
      try {
        await sdkCore.unpinFromIpfs(params.binCtx.ctx, entry.contentCid);
      } catch {
        // Non-blocking
      }
    }
  }

  // Publish empty bin metadata
  const newBinSeq = params.binState.sequenceNumber + 1;
  const metadata: RecycleBinMetadata = {
    version: BIN_METADATA_VERSION,
    sequenceNumber: newBinSeq,
    entries: [],
  };

  await saveBinMetadata({ metadata, binCtx: params.binCtx });

  return {
    updatedBinState: {
      entries: [],
      sequenceNumber: newBinSeq,
      ipnsName: params.binState.ipnsName,
    },
  };
}

/**
 * Purge expired bin entries based on retention period.
 *
 * Filters entries past their retention, cleans up CIDs (best-effort),
 * and publishes updated bin metadata in a single IPNS publish.
 *
 * @returns Number of purged entries and updated bin state
 */
export async function purgeExpiredEntries(params: {
  binState: BinState;
  retentionDays: number;
  binCtx: BinOperationContext;
}): Promise<{ purgedCount: number; updatedState: BinState }> {
  const retentionMs = params.retentionDays * 24 * 60 * 60 * 1000;
  const now = Date.now();

  const expired = params.binState.entries.filter((e) => now - e.deletedAt > retentionMs);
  if (expired.length === 0) {
    return { purgedCount: 0, updatedState: params.binState };
  }

  // Remove expired entries and publish updated bin BEFORE cleanup.
  // This ensures bin metadata is consistent even if CID unpins fail.
  const expiredIds = new Set(expired.map((e) => e.id));
  const remainingEntries = params.binState.entries.filter((e) => !expiredIds.has(e.id));
  const newBinSeq = params.binState.sequenceNumber + 1;

  const metadata: RecycleBinMetadata = {
    version: BIN_METADATA_VERSION,
    sequenceNumber: newBinSeq,
    entries: remainingEntries,
  };

  await saveBinMetadata({ metadata, binCtx: params.binCtx });

  // Best-effort CID cleanup for expired entries (after metadata is saved)
  for (const entry of expired) {
    if (entry.contentCid) {
      try {
        await sdkCore.unpinFromIpfs(params.binCtx.ctx, entry.contentCid);
      } catch {
        // Best-effort: CID cleanup failures are non-blocking
      }
    }
    // Also clean up version CIDs to recover quota
    if (entry.versionCids) {
      for (const vc of entry.versionCids) {
        try {
          await sdkCore.unpinFromIpfs(params.binCtx.ctx, vc.cid);
        } catch {
          // Best-effort
        }
      }
    }
  }

  return {
    purgedCount: expired.length,
    updatedState: {
      entries: remainingEntries,
      sequenceNumber: newBinSeq,
      ipnsName: params.binState.ipnsName,
    },
  };
}
