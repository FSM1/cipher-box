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
} from '@cipherbox/core';
import type { SealedChildRef } from '@cipherbox/core';
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
// Internal helpers: unpin
// ---------------------------------------------------------------------------
// NOTE(phase 65 — bin re-link): captureFileCids and walkDeletedSubtree were
// removed in phase 62 because they accessed FilePointer/FolderEntry types which
// were retired in the node/v3 upgrade. The equivalent phase-65 helpers will
// enumerate Node children and collect versionCids from NodeContent rather than
// from standalone FileMetadata IPNS records.

/**
 * Best-effort unpin of every content/version/descendant CID recorded on a bin
 * entry. Each unpin is independently try/caught so one failure never blocks the
 * rest. Shared by emptyBin, permanentDeleteFromBin and purgeExpiredEntries so all
 * three paths unpin the SAME set (the prior bug: the first two only looked at
 * entry.contentCid and never looped versionCids/descendantCids).
 */
async function unpinEntryCids(ctx: SdkContext, entry: BinEntry): Promise<void> {
  const cids: string[] = [];
  if (entry.contentCid) cids.push(entry.contentCid);
  for (const vc of entry.versionCids ?? []) cids.push(vc.cid);
  for (const dc of entry.descendantCids ?? []) cids.push(dc.cid);

  for (const cid of cids) {
    try {
      await sdkCore.unpinFromIpfs(ctx, cid);
    } catch {
      // Best-effort: CID unpin failures are non-blocking.
    }
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Number of resolve attempts in loadBin before falling back to empty state. */
const LOAD_BIN_MAX_ATTEMPTS = 6;
/** Base backoff (ms) between loadBin resolve retries. */
const LOAD_BIN_RETRY_DELAY_MS = 500;

/**
 * Load the recycle bin metadata from IPNS.
 *
 * If no bin IPNS record exists yet (first login / never deleted anything),
 * returns an in-memory empty BinState so that deleteToBin can create the first
 * record. The first addToBin lazily publishes the real record at
 * sequenceNumber 1 (0 + 1), which matches the API create-path.
 *
 * Crucially, loadBin NEVER publishes on a null resolve. A null is not a
 * reliable "bin is empty" signal: resolveIpnsRecord also returns null on a
 * cold-cache miss right after a page reload, or while a concurrent
 * loadBin()/delete is mid-flight. Publishing an empty record here is
 * destructive — the bin publish path carries no expectedSequenceNumber, so the
 * API blindly increments the sequence and overwrites the real record's CID with
 * the empty-bin CID (apps/api ipns.service upsertFolderIpns), wiping every
 * entry. The API's /ipns/resolve already falls back to its synchronously-written
 * DB cache, so a client-side null means the record is genuinely absent at that
 * instant; we recover transient nulls with a bounded retry instead of writing.
 *
 * @returns Current bin state (never null — in-memory empty state if no record exists)
 */
export async function loadBin(params: { binCtx: BinOperationContext }): Promise<BinState> {
  // Bounded retry: convert a transient null (cold resolve cache after reload, or
  // a concurrent in-flight publish) into a successful load before falling back
  // to empty state. Never publishes.
  for (let attempt = 0; attempt < LOAD_BIN_MAX_ATTEMPTS; attempt++) {
    const loaded = await loadBinMetadataInternal({
      userPrivateKey: params.binCtx.userPrivateKey,
      ctx: params.binCtx.ctx,
    });

    if (loaded) {
      return {
        entries: loaded.metadata.entries,
        sequenceNumber: loaded.metadata.sequenceNumber,
        ipnsName: loaded.ipnsName,
      };
    }

    if (attempt < LOAD_BIN_MAX_ATTEMPTS - 1) {
      await new Promise((r) => setTimeout(r, LOAD_BIN_RETRY_DELAY_MS));
    }
  }

  // No bin IPNS record resolved after all retries — treat as a genuinely new
  // bin. Return in-memory empty state WITHOUT publishing. The first addToBin
  // publishes at sequenceNumber 0 + 1 = 1, matching the API create-path.
  const binIpns = await deriveBinIpnsKeypair(params.binCtx.userPrivateKey);
  return {
    entries: [],
    sequenceNumber: 0,
    ipnsName: binIpns.ipnsName,
  };
}

/**
 * Add item to recycle bin.
 *
 * Removes the item from the folder metadata (via deleteFromFolder),
 * creates a BinEntry, appends to bin metadata, and publishes both.
 *
 * Ordering is fail-closed and CRITICAL (locked design):
 *   walk subtree → revoke shares for every collected ipnsName → mutate folder +
 *   publish → build bin entry (with captured CIDs) → publish bin.
 * Revoke MUST precede the destructive folder mutation: the only acceptable
 * residual bad state is "shares revoked but item still present" (recoverable);
 * "item deleted but shares still active" would orphan sharees on the eventual
 * empty-bin unpin and is NEVER allowed.
 *
 * The subtree walk (folder deletes) is fail-closed on structure: if a descendant
 * folder's metadata can't be enumerated, the whole delete aborts BEFORE the
 * folder mutation. Per-file content-CID capture is best-effort.
 *
 * @param params.revokeSharesForItemsFn - Issues POST /shares/revoke-for-items.
 *   Injected so the API boundary stays mockable. Omitted only in legacy callers.
 * @returns The removed item from the folder
 */
export async function addToBin(params: {
  folderIpnsName: string;
  childId: string;
  parentPath: string;
  folderTree: FolderTree;
  binState: BinState;
  binCtx: BinOperationContext;
  revokeSharesForItemsFn?: (ipnsNames: string[]) => Promise<void>;
}): Promise<{ removedItem: SealedChildRef; updatedBinState: BinState }> {
  void params;
  throw new Error('not implemented — phase 65 (bin re-link)');
}

/**
 * Restore an item from the recycle bin back to a folder.
 *
 * PHASE 62 STUB: Phase 65 (bin re-link) will re-implement this using the
 * Node/SealedChildRef model — a SealedChildRef stored on the BinEntry's
 * nodeRef field is re-inserted into the target folder's write-body.
 * The old FolderChild/FilePointer/originalFolderKeyEncrypted fields are
 * removed from BinEntry; see docs/METADATA_SCHEMAS.md §BinEntry.
 *
 * @stub phase 65 (bin re-link)
 */
export async function restoreFromBin(params: {
  entryId: string;
  targetFolderIpnsName: string;
  folderTree: FolderTree;
  binState: BinState;
  binCtx: BinOperationContext;
}): Promise<{ restoredItem: SealedChildRef; updatedBinState: BinState }> {
  void params;
  throw new Error('not implemented — phase 65 (bin re-link)');
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

  // Unpin content + version + descendant CIDs (best-effort, shared helper).
  await unpinEntryCids(params.binCtx.ctx, entry);

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
  // Best-effort CID cleanup for each entry — content + versions + descendant
  // subtree (shared helper; previously only entry.contentCid was unpinned).
  for (const entry of params.binState.entries) {
    await unpinEntryCids(params.binCtx.ctx, entry);
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

  // Best-effort CID cleanup for expired entries (after metadata is saved):
  // content + versions + descendant subtree via the shared helper.
  for (const entry of expired) {
    await unpinEntryCids(params.binCtx.ctx, entry);
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
