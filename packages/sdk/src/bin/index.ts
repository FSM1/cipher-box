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
  sealChildWriteKey,
  unsealChildReadKey,
  unsealChildWriteKey,
  unsealNode,
  type BinEntry,
  type RecycleBinMetadata,
} from '@cipherbox/core';
import type { SealedChildRef, Node, PublishedNode, WriteChildRef } from '@cipherbox/core';
import { bytesToHex, hexToBytes, wrapKey } from '@cipherbox/crypto';
import type { FolderTree } from '../state/folder-tree';
import type { FolderState } from '../types';

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
// Internal helpers: write-body preservation (D-03)
// ---------------------------------------------------------------------------

/**
 * Resolve the write-body params (`writeKey` + current `writeChildren`) the bin
 * publish sites must thread into `updateFolderMetadataAndPublish` so the
 * republished owned folder PRESERVES its existing write chain (D-03).
 *
 * Mirrors CipherBoxClient.getWriteBodyParams (client.ts): a legacy zero-fallback
 * writeKey returns `{}` (write-body-less publish, pre-D-03 behavior); an
 * in-memory `folder.metadata.writeBody` is preferred; otherwise the CURRENT
 * on-wire node is unsealed once. A present-but-unopenable write-body throws
 * fail-closed (T-68.1-01-03). Never zeroes folder keys (caller-owned, D-09).
 */
async function getWriteBodyParams(
  folder: FolderState,
  ctx: SdkContext
): Promise<{ writeKey?: Uint8Array; writeChildren?: WriteChildRef[] }> {
  const wk = folder.writeKey;
  if (!wk || wk.length !== 32 || wk.every((b) => b === 0)) {
    return {};
  }
  if (folder.metadata?.writeBody) {
    return { writeKey: wk, writeChildren: folder.metadata.writeBody.writeChildren };
  }
  const resolved = await sdkCore.resolveIpnsRecord(folder.ipnsName, ctx);
  if (!resolved) {
    // 72-04 SC#2: a real writeKey is present but the resolve genuinely
    // came back null (transient IPNS resolve miss) — fail CLOSED rather
    // than returning writeChildren: [], which would let the next publish
    // seal an EMPTY write-body and silently discard the entire write
    // chain. Distinct from the `!writeSealed` case below (a structurally
    // never-write-capable folder), which stays fail-open (Pitfall 3 / A1).
    // Mirrors CipherBoxClient.getWriteBodyParams (client.ts) — keep both
    // copies identical (Plan 08 dedupe precondition).
    throw new Error(
      `getWriteBodyParams: transient IPNS resolve miss for folder ${folder.ipnsName}; refusing to seal an empty write-body and discard the write chain`
    );
  }
  const raw = await sdkCore.fetchFromIpfs(ctx, resolved.cid);
  const published = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
  if (!published.writeSealed) return { writeKey: wk, writeChildren: [] };
  const node = await unsealNode(published, folder.folderKey, wk);
  return { writeKey: wk, writeChildren: node.writeBody?.writeChildren ?? [] };
}

/**
 * Adopt a successful `updateFolderMetadataAndPublish` result into the
 * in-memory FolderState, INCLUDING the unsealed `metadata` Node mirror
 * (68.1-22 — mirrors CipherBoxClient.adoptPublishedFolderState).
 *
 * The bin publish sites previously discarded the publish result entirely,
 * leaving `folderState.sequenceNumber` one step behind the wire — so the very
 * next publish against the same folder (e.g. restoreFromBin right after
 * deleteToBin) hit the server's anti-rollback gate with a 409 Conflict.
 */
function adoptPublishedFolderState(
  folderTree: FolderTree,
  folder: FolderState,
  publishedChildren: SealedChildRef[],
  newSequenceNumber: bigint,
  publishedWriteChildren?: WriteChildRef[]
): void {
  folder.children = publishedChildren;
  folder.sequenceNumber = newSequenceNumber;
  folder.lastLoadedAt = Date.now();
  if (folder.metadata) {
    folder.metadata.children = publishedChildren;
    if (publishedWriteChildren) {
      if (folder.metadata.writeBody) {
        folder.metadata.writeBody.writeChildren = publishedWriteChildren;
      } else {
        // 68.1-29: create the write-body mirror when the folder was loaded with a
        // read-only metadata mirror but this publish sealed a real write chain, so
        // the next getWriteBodyParams/DFS read sees the new WriteChildRefs (mirrors
        // CipherBoxClient.adoptPublishedFolderState).
        folder.metadata.writeBody = {
          ipnsPrivateKey: new Uint8Array(folder.ipnsKeypair.privateKey),
          writeChildren: publishedWriteChildren,
        };
      }
    }
  }
  folderTree.set(folder.ipnsName, folder);
}

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
    publishedNode.id, // plaintext id — immutable across generations
    publishedNode.kind, // plaintext kind — immutable across generations
    // Generation-source rule (§2.6, Pitfall 1): the AAD MUST use childRef.generation
    // (the PARENT MIRROR that childRef.readKeySealed was sealed under), NOT
    // publishedNode.generation. A stale-CID IPNS serve makes the envelope generation
    // diverge from the seal generation, failing GCM auth closed even though the
    // parent's folder state is current. Mirrors moveItem / navigate.ts.
    childRef.generation
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
      // Capture the generation that matches nodeReadKey (the readKey wrapped by
      // childRef.readKeySealed, unsealed under childRef.generation above). restoreFromBin
      // re-seals with nodeRef.generation, so it must equal the seal generation — using
      // the possibly-stale publishedNode.generation would store an inconsistent witness.
      generation: childRef.generation,
      createdAt: 0,
      modifiedAt: 0,
    },
  };

  // Resolve the folder's write-body params BEFORE the durable bin write.
  // getWriteBodyParams can resolve/fetch/unseal and THROW, so surface that
  // failure here rather than AFTER saveBinMetadata has made the bin entry
  // durable — a throw once the bin entry is persisted (but the folder delete has
  // not happened) leaves the item in BOTH the bin and the folder and, on retry,
  // accumulates a duplicate bin entry. Preserve the existing write-body verbatim
  // (D-03) — the WriteChildRef is intentionally RETAINED here (soft-delete),
  // not dropped, so a later restoreFromBin can re-home it to a different
  // parent (SC#3, 72-05). The symmetric release point that DROPS it is
  // permanentDeleteFromBin (72-05, Open Question 1) — a soft-deleted item
  // that is never restored and is later permanently deleted has its
  // lingering ref dropped there instead.
  const writeBodyParams = await getWriteBodyParams(folderState, binCtx.ctx);

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

  // 10. Publish updated folder (destructive — must happen after the restore key
  //     is durable). writeBodyParams was resolved above (before saveBinMetadata).
  const { newSequenceNumber, publishedChildren, publishedWriteChildren } =
    await sdkCore.updateFolderMetadataAndPublish({
      children: updatedChildren,
      folderKey: folderState.folderKey,
      ...writeBodyParams,
      ipnsPrivateKey: folderState.ipnsKeypair.privateKey,
      ipnsPublicKey: folderState.ipnsKeypair.publicKey,
      ipnsName: folderIpnsName,
      sequenceNumber: folderState.sequenceNumber,
      ctx: binCtx.ctx,
      nodeId: folderState.nodeId,
      nodeGeneration: folderState.nodeGeneration,
    });

  // Adopt the publish result so the next publish against this folder does not
  // 409 on the server's anti-rollback sequence gate (68.1-22).
  adoptPublishedFolderState(
    folderTree,
    folderState,
    publishedChildren,
    newSequenceNumber,
    publishedWriteChildren ?? writeBodyParams.writeChildren
  );

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
  /**
   * The bin entry's original parent FolderState, when resolvable — SC#3
   * (72-05). Enables cross-folder WriteChildRef re-homing when restoring to
   * a DIFFERENT parent than the original. Omitted (or the original parent
   * could not be resolved upstream, e.g. it was itself deleted/moved since
   * the soft-delete) => the restore proceeds read-plane-only exactly as
   * before this plan (fail-open, T-72-05-03) — it never throws or blocks
   * the restore.
   */
  sourceFolder?: FolderState;
}): Promise<{ restoredItem: SealedChildRef; updatedBinState: BinState }> {
  const { entryId, targetFolderIpnsName, folderTree, binState, binCtx, sourceFolder } = params;

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

  // 6. Add restored ref to target folder and publish.
  //    Idempotent: if the item is already present by ipnsName (retry after saveBinMetadata
  //    failure), reuse the existing children list to avoid duplicating the child ref.
  const alreadyInFolder = targetFolder.children.some((c) => c.ipnsName === entry.nodeIpnsName);
  const childrenForPublish = alreadyInFolder
    ? targetFolder.children
    : [...targetFolder.children, restoredItem];
  const targetWriteBodyParams = await getWriteBodyParams(targetFolder, binCtx.ctx);
  const baseTargetWriteChildren = targetWriteBodyParams.writeChildren;
  let rehomedTargetWriteChildren = targetWriteBodyParams.writeChildren;

  // SC#3 (72-05): re-home the WriteChildRef when restoring to a DIFFERENT
  // parent than the original. Reuses moveItem's (68.1-31) dest-before-source
  // unseal/reseal/drop pattern (client.ts ~L2753-2818), keyed strictly by the
  // node's own UUID (nodeId, captured on BinEntry.nodeRef.id at addToBin
  // time — never entry.nodeIpnsName / targetFolderIpnsName, which are
  // ipnsName-keyed). Pitfall 4: `generation` here is `restoredItem.generation`
  // (== nodeRef.generation) — the SAME value already used for the read-plane
  // reseal above — never a second, independently-derived generation.
  let sourceWriteBodyParams: { writeKey?: Uint8Array; writeChildren?: WriteChildRef[] } = {};
  let baseSourceWriteChildren: WriteChildRef[] | undefined;
  let rehomedSourceWriteChildren: WriteChildRef[] | undefined;
  let didRehome = false;

  if (sourceFolder && sourceFolder.ipnsName !== targetFolderIpnsName) {
    try {
      sourceWriteBodyParams = await getWriteBodyParams(sourceFolder, binCtx.ctx);
      baseSourceWriteChildren = sourceWriteBodyParams.writeChildren;
      rehomedSourceWriteChildren = sourceWriteBodyParams.writeChildren;

      if (!targetWriteBodyParams.writeKey || !sourceWriteBodyParams.writeKey) {
        console.warn(
          `[CipherBox] restoreFromBin: source or destination folder ${sourceFolder.ipnsName} -> ` +
            `${targetFolderIpnsName} is read-only — the restored item will not be write-capable ` +
            'in its new location'
        );
      } else {
        // Write plane is keyed by node UUID (nodeId) — NEVER the ipnsName-based
        // entry.nodeIpnsName / targetFolderIpnsName handles.
        const movedWriteRef = sourceWriteBodyParams.writeChildren?.find(
          (wc) => wc.childId === nodeId
        );
        if (movedWriteRef) {
          let movedWriteKey: Uint8Array | null = null;
          try {
            movedWriteKey = await unsealChildWriteKey(
              movedWriteRef.writeKeySealed,
              sourceWriteBodyParams.writeKey,
              nodeId,
              nodeKind,
              generation
            );
            const writeKeySealed = await sealChildWriteKey(
              movedWriteKey,
              targetWriteBodyParams.writeKey,
              nodeId,
              nodeKind,
              generation
            );
            rehomedTargetWriteChildren = [
              ...(targetWriteBodyParams.writeChildren ?? []).filter((wc) => wc.childId !== nodeId),
              { childId: nodeId, writeKeySealed },
            ];
            rehomedSourceWriteChildren = (sourceWriteBodyParams.writeChildren ?? []).filter(
              (wc) => wc.childId !== nodeId
            );
            didRehome = true;
          } finally {
            // Zero the recovered child writeKey on every exit path —
            // engine-derived, terminal-owned (D-09). Never zero
            // sourceWriteBodyParams.writeKey / targetWriteBodyParams.writeKey
            // (tree/caller-owned).
            movedWriteKey?.fill(0);
          }
        }
        // else: no source WriteChildRef for this node (pre-write-plane or
        // already read-only) — nothing to re-home, lists stay verbatim.
      }
    } catch (err) {
      // Fail OPEN (T-72-05-03): a failure resolving the SOURCE side's
      // write-body must never block the restore — it degrades to
      // read-plane-only re-linking, exactly as if sourceFolder had not been
      // supplied at all.
      console.warn(
        `[CipherBox] restoreFromBin: source folder ${sourceFolder.ipnsName} write-body resolve ` +
          'failed — restoring read-plane only (no re-homing):',
        err
      );
      rehomedSourceWriteChildren = undefined;
      baseSourceWriteChildren = undefined;
      didRehome = false;
    }
  }

  // Publish TARGET (restore destination) before SOURCE (original parent) —
  // dest-before-source (D-12) — so a crash between publishes never orphans
  // the node's write capability entirely.
  const { newSequenceNumber, publishedChildren, publishedWriteChildren } =
    await sdkCore.updateFolderMetadataAndPublish({
      children: childrenForPublish,
      folderKey: targetFolder.folderKey,
      writeKey: targetWriteBodyParams.writeKey,
      writeChildren: rehomedTargetWriteChildren,
      baseWriteChildren: baseTargetWriteChildren,
      ipnsPrivateKey: targetFolder.ipnsKeypair.privateKey,
      ipnsPublicKey: targetFolder.ipnsKeypair.publicKey,
      ipnsName: targetFolderIpnsName,
      sequenceNumber: targetFolder.sequenceNumber,
      ctx: binCtx.ctx,
      nodeId: targetFolder.nodeId,
      nodeGeneration: targetFolder.nodeGeneration,
    });

  // Adopt the publish result so the next publish against this folder does not
  // 409 on the server's anti-rollback sequence gate (68.1-22).
  adoptPublishedFolderState(
    folderTree,
    targetFolder,
    publishedChildren,
    newSequenceNumber,
    publishedWriteChildren ?? rehomedTargetWriteChildren
  );

  if (didRehome && sourceFolder) {
    const {
      newSequenceNumber: sourceSeq,
      publishedChildren: sourcePublishedChildren,
      publishedWriteChildren: sourcePublishedWriteChildren,
    } = await sdkCore.updateFolderMetadataAndPublish({
      children: sourceFolder.children,
      folderKey: sourceFolder.folderKey,
      writeKey: sourceWriteBodyParams.writeKey,
      writeChildren: rehomedSourceWriteChildren,
      baseWriteChildren: baseSourceWriteChildren,
      ipnsPrivateKey: sourceFolder.ipnsKeypair.privateKey,
      ipnsPublicKey: sourceFolder.ipnsKeypair.publicKey,
      ipnsName: sourceFolder.ipnsName,
      sequenceNumber: sourceFolder.sequenceNumber,
      ctx: binCtx.ctx,
      nodeId: sourceFolder.nodeId,
      nodeGeneration: sourceFolder.nodeGeneration,
    });

    adoptPublishedFolderState(
      folderTree,
      sourceFolder,
      sourcePublishedChildren,
      sourceSeq,
      sourcePublishedWriteChildren ?? rehomedSourceWriteChildren
    );
  }

  // 7. Remove entry from bin and publish updated bin metadata
  const remainingEntries = binState.entries.filter((e) => e.id !== entryId);
  const newBinSeq = binState.sequenceNumber + 1;
  const metadata: RecycleBinMetadata = {
    version: BIN_METADATA_VERSION,
    sequenceNumber: newBinSeq,
    entries: remainingEntries,
  };
  await saveBinMetadata({ metadata, binCtx });

  // 8. Best-effort: verify the restored child's OWN IPNS record still resolves.
  //    Runs AFTER the durable bin cleanup (finding 16) so this diagnostic
  //    network round-trip never delays removing the entry from the bin — it is
  //    verify-only (console.warn), never a throw, and must not gate cleanup.
  //    restoreFromBin only re-links the SealedChildRef into the parent (above) —
  //    it never re-publishes the child's own record, and the bin entry carries no
  //    child ipnsPrivateKey, so re-minting here is impossible. deleteToBin does
  //    NOT unenroll on soft-delete, so the child record should normally still be
  //    TEE-republish-enrolled and resolvable. If it is NOT resolvable, warn rather
  //    than silently treating a dead folder as navigable.
  try {
    const childResolved = await sdkCore.resolveIpnsRecord(entry.nodeIpnsName, binCtx.ctx);
    if (!childResolved) {
      console.warn(
        `[CipherBox] restoreFromBin: restored child ${entry.nodeIpnsName} (bin entry ${entryId}) ` +
          'does not resolve — its own IPNS record appears unavailable. The child was re-linked ' +
          'into the parent folder, but navigating into it may fail until the record republishes. ' +
          'No re-mint is possible here (bin entries do not carry the child ipnsPrivateKey).'
      );
    }
  } catch (err) {
    console.warn(
      `[CipherBox] restoreFromBin: resolve check for restored child ${entry.nodeIpnsName} failed:`,
      err
    );
  }

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
  /**
   * The bin entry's original parent FolderState, when resolvable (SC#1
   * symmetry / Open Question 1, 72-05). `addToBin` RETAINS the removed
   * child's WriteChildRef in the original parent's write-body (so a later
   * `restoreFromBin` can re-home it) — permanent removal is the symmetric
   * release point that drops it. Omitted (or the original parent could not
   * be resolved upstream) => permanent-delete proceeds exactly as before
   * this plan (fail-open — never blocks CID cleanup + entry removal).
   */
  originalParent?: FolderState;
  folderTree?: FolderTree;
}): Promise<{ updatedBinState: BinState }> {
  const entry = params.binState.entries.find((e) => e.id === params.entryId);
  if (!entry) throw new Error('Bin entry not found');

  // Unpin content + version + descendant CIDs (best-effort, shared helper).
  await unpinEntryCids(params.binCtx.ctx, entry);

  // SC#1 symmetry (Open Question 1): drop the lingering WriteChildRef from
  // the original parent's write-body, by the node UUID captured on
  // BinEntry.nodeRef.id at addToBin time (Pitfall 4 — use the captured
  // witness, not a fresh resolve). Fail OPEN on any failure: a resolve miss
  // or publish failure here must never block the CID cleanup + entry
  // removal below (matches deleteItem's hygiene posture, Pitfall 2).
  if (params.originalParent && entry.nodeRef?.id) {
    const originalParent = params.originalParent;
    const nodeId = entry.nodeRef.id;
    try {
      const writeBodyParams = await getWriteBodyParams(originalParent, params.binCtx.ctx);
      const hasLingeringRef = writeBodyParams.writeChildren?.some((wc) => wc.childId === nodeId);
      if (writeBodyParams.writeKey && hasLingeringRef) {
        const baseWriteChildren = writeBodyParams.writeChildren;
        const trimmedWriteChildren = (writeBodyParams.writeChildren ?? []).filter(
          (wc) => wc.childId !== nodeId
        );
        const { newSequenceNumber, publishedChildren, publishedWriteChildren } =
          await sdkCore.updateFolderMetadataAndPublish({
            children: originalParent.children,
            folderKey: originalParent.folderKey,
            writeKey: writeBodyParams.writeKey,
            writeChildren: trimmedWriteChildren,
            baseWriteChildren,
            ipnsPrivateKey: originalParent.ipnsKeypair.privateKey,
            ipnsPublicKey: originalParent.ipnsKeypair.publicKey,
            ipnsName: originalParent.ipnsName,
            sequenceNumber: originalParent.sequenceNumber,
            ctx: params.binCtx.ctx,
            nodeId: originalParent.nodeId,
            nodeGeneration: originalParent.nodeGeneration,
          });
        if (params.folderTree) {
          adoptPublishedFolderState(
            params.folderTree,
            originalParent,
            publishedChildren,
            newSequenceNumber,
            publishedWriteChildren ?? trimmedWriteChildren
          );
        } else {
          originalParent.children = publishedChildren;
          originalParent.sequenceNumber = newSequenceNumber;
        }
      }
    } catch (err) {
      console.warn(
        `[CipherBox] permanentDeleteFromBin: failed to drop lingering WriteChildRef from ` +
          `original parent ${originalParent.ipnsName}:`,
        err
      );
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
