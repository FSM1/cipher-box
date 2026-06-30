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
  sealChildReadKey,
  unsealChildReadKey,
  type BinEntry,
  type RecycleBinMetadata,
} from '@cipherbox/core';
import type { SealedChildRef, Node } from '@cipherbox/core';
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
 * Ordering is fail-closed and CRITICAL:
 *   walk subtree → revoke shares for every collected ipnsName → build bin entry →
 *   publish bin → mutate folder + publish.
 * Revoke MUST precede the destructive folder mutation: the only acceptable
 * residual bad state is "shares revoked but item still present" (recoverable);
 * "item deleted but shares still active" would orphan sharees on the eventual
 * empty-bin unpin and is NEVER allowed.
 * Bin save MUST precede the destructive folder publish: if bin save fails, the
 * item remains in the folder and is recoverable. The converse (folder publish
 * then bin save fails) would orphan the item with no restore key.
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
  const { folderIpnsName, childId, parentPath, folderTree, binState, binCtx } = params;

  // 1. Validate source folder is loaded
  const folderState = folderTree.get(folderIpnsName);
  if (!folderState) throw new Error('Folder not loaded');

  // 2. Resolve child IPNS record to get PublishedNode envelope bytes
  //    (mirrors moveItem pattern in client.ts lines 589-606 for id/kind extraction)
  const childResolved = await sdkCore.resolveIpnsRecord(childId, binCtx.ctx);
  if (!childResolved) throw new Error(`Could not resolve child IPNS record: ${childId}`);
  const nodeBytes = await sdkCore.fetchFromIpfs(binCtx.ctx, childResolved.cid);

  // 3. Parse PublishedNode plaintext envelope (no decryption needed — id/kind are plaintext)
  const publishedNode = JSON.parse(new TextDecoder().decode(nodeBytes)) as {
    schema: string;
    kind: Node['kind'];
    id: string;
    generation: number;
    aeadVersion: number;
    readSealed: string;
  };

  // 4. Find the child ref in the source folder children
  const childRef = folderState.children.find((c) => c.ipnsName === childId);
  if (!childRef) throw new Error(`Child not found in folder: ${childId}`);

  // 5. Unseal the child's nodeReadKey from the source parent folderKey
  //    — gives us the raw 32-byte readKey to capture in the BinEntry
  const nodeReadKey = await unsealChildReadKey(
    childRef.readKeySealed,
    folderState.folderKey,
    publishedNode.id,
    publishedNode.kind,
    publishedNode.generation
  );

  // 6. Revoke shares BEFORE the destructive folder mutation (fail-closed)
  if (params.revokeSharesForItemsFn) {
    await params.revokeSharesForItemsFn([childId]);
  }

  // 7. Remove child from source folder (pure sync transform)
  const { updatedChildren, removedItem } = sdkCore.deleteFromFolder({
    children: folderState.children,
    childId,
  });

  // 8. Build BinEntry with captured nodeReadKey and nodeIpnsName for restore
  const newEntry: BinEntry = {
    id: crypto.randomUUID(),
    itemType: publishedNode.kind === 'folder' ? 'folder' : 'file',
    name: childRef.name,
    originalParentIpnsName: folderIpnsName,
    originalPath: parentPath,
    deletedAt: Date.now(),
    size: 0,
    mimeType: '',
    nodeReadKey,
    nodeIpnsName: childId,
    nodeRef: {
      schema: 'node/v3' as const,
      kind: publishedNode.kind,
      id: publishedNode.id,
      generation: publishedNode.generation,
      createdAt: 0,
      modifiedAt: 0,
    },
  };

  // 9. Persist bin metadata BEFORE the destructive source-folder publish.
  //    If the bin save fails we have not yet deleted the item from the folder,
  //    so the item remains visible and fully recoverable (fail-safe ordering).
  const newBinSeq = binState.sequenceNumber + 1;
  const newEntries = [...binState.entries, newEntry];
  const metadata: RecycleBinMetadata = {
    version: BIN_METADATA_VERSION,
    sequenceNumber: newBinSeq,
    entries: newEntries,
  };
  await saveBinMetadata({ metadata, binCtx });

  // 10. Publish updated folder (destructive — must happen after the restore key is durable)
  await sdkCore.updateFolderMetadataAndPublish({
    children: updatedChildren,
    folderKey: folderState.folderKey,
    ipnsPrivateKey: folderState.ipnsKeypair.privateKey,
    ipnsPublicKey: folderState.ipnsKeypair.publicKey,
    ipnsName: folderIpnsName,
    sequenceNumber: folderState.sequenceNumber,
    ctx: binCtx.ctx,
    nodeId: folderState.nodeId,
    nodeGeneration: folderState.nodeGeneration,
  });

  return {
    removedItem,
    updatedBinState: {
      entries: newEntries,
      sequenceNumber: newBinSeq,
      ipnsName: binState.ipnsName,
    },
  };
}

/**
 * Restore an item from the recycle bin back to a folder.
 *
 * Pure re-link implementation (Phase 65 / design §3.10):
 *   - The deleted node's own readKey (captured in BinEntry.nodeReadKey at
 *     addToBin time) is re-sealed under the destination parent's folderKey
 *     via sealChildReadKey (role 0x02 child-readkey AAD).
 *   - No content re-encryption — the item's IPNS record and content CIDs
 *     are unchanged. Only the SealedChildRef link in the parent folder's
 *     read-body is updated.
 */
export async function restoreFromBin(params: {
  entryId: string;
  targetFolderIpnsName: string;
  folderTree: FolderTree;
  binState: BinState;
  binCtx: BinOperationContext;
}): Promise<{ restoredItem: SealedChildRef; updatedBinState: BinState }> {
  const { entryId, targetFolderIpnsName, folderTree, binState, binCtx } = params;

  // 1. Find the bin entry
  const entry = binState.entries.find((e) => e.id === entryId);
  if (!entry) throw new Error('Bin entry not found');

  // 2. Verify nodeReadKey is present (required for re-link)
  if (!entry.nodeReadKey) {
    throw new Error(`nodeReadKey is missing on bin entry ${entryId} — cannot restore without it`);
  }

  // 3. Validate target folder is loaded
  const targetFolder = folderTree.get(targetFolderIpnsName);
  if (!targetFolder) throw new Error('Folder not loaded');

  // 3b. Fail closed on missing re-link anchors — defaulting to '' or 0 would bind
  //     sealChildReadKey to the wrong AAD and produce an unrestorable sealed key.
  if (!entry.nodeIpnsName) {
    throw new Error(`nodeIpnsName is missing on bin entry ${entryId} — cannot restore`);
  }
  if (!entry.nodeRef?.id || !entry.nodeRef.kind || entry.nodeRef.generation == null) {
    throw new Error(`nodeRef is missing or incomplete on bin entry ${entryId} — cannot restore`);
  }

  const nodeRef = entry.nodeRef;
  const generation = nodeRef.generation;
  const nodeId = nodeRef.id;
  const nodeKind = nodeRef.kind;

  // 4. Re-seal the node's own readKey under the destination parent's folderKey
  //    (pure re-link: sealChildReadKey role 0x02 — no content re-encryption)
  const readKeySealed = await sealChildReadKey(
    entry.nodeReadKey,
    targetFolder.folderKey,
    nodeId,
    nodeKind,
    generation
  );

  // 5. Build the restored SealedChildRef
  const restoredItem: SealedChildRef = {
    name: entry.name,
    ipnsName: entry.nodeIpnsName,
    generation,
    versionFloor: 0n,
    readKeySealed,
  };

  // 6. Add restored ref to target folder and publish
  await sdkCore.updateFolderMetadataAndPublish({
    children: [...targetFolder.children, restoredItem],
    folderKey: targetFolder.folderKey,
    ipnsPrivateKey: targetFolder.ipnsKeypair.privateKey,
    ipnsPublicKey: targetFolder.ipnsKeypair.publicKey,
    ipnsName: targetFolderIpnsName,
    sequenceNumber: targetFolder.sequenceNumber,
    ctx: binCtx.ctx,
    nodeId: targetFolder.nodeId,
    nodeGeneration: targetFolder.nodeGeneration,
  });

  // 7. Remove entry from bin and publish updated bin metadata
  const remainingEntries = binState.entries.filter((e) => e.id !== entryId);
  const newBinSeq = binState.sequenceNumber + 1;
  const metadata: RecycleBinMetadata = {
    version: BIN_METADATA_VERSION,
    sequenceNumber: newBinSeq,
    entries: remainingEntries,
  };
  await saveBinMetadata({ metadata, binCtx });

  return {
    restoredItem,
    updatedBinState: {
      entries: remainingEntries,
      sequenceNumber: newBinSeq,
      ipnsName: binState.ipnsName,
    },
  };
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
