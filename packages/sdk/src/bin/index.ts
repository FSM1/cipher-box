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
import { bytesToHex, clearBytes, hexToBytes, unwrapKey, wrapKey } from '@cipherbox/crypto';
import type { FolderTree } from '../state/folder-tree';
import { reencryptFileMetadataForFolderChange } from '../reencrypt';
import * as shareOps from '../share';

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
// Internal helpers: subtree walk (IPNS names + content CIDs) and unpin
// ---------------------------------------------------------------------------

/** A captured content/version CID with its plaintext size, for unpin + quota. */
type CapturedCid = { cid: string; size: number };

/**
 * Result of walking a deleted subtree: every node's IPNS name (for share
 * revocation) and every descendant content + version CID (for unpin).
 */
type SubtreeWalkResult = {
  /** Folder's own ipnsName + every descendant file fileMetaIpnsName + subfolder ipnsName. */
  ipnsNames: string[];
  /** Flattened content + version CIDs of every descendant file. */
  descendantCids: CapturedCid[];
};

/**
 * Capture a single file's content + version CIDs from its FileMetadata.
 *
 * Best-effort: a file whose metadata cannot be resolved/decrypted is skipped
 * (returns empty) — its IPNS name is still revoked/unenrolled by the caller, but
 * its content CID can't be captured for unpin. This matches the locked policy:
 * within a successfully-enumerated walk, an individual file's CID-capture failure
 * is non-fatal.
 */
async function captureFileCids(
  fileMetaIpnsName: string,
  folderKey: Uint8Array,
  ctx: SdkContext
): Promise<CapturedCid[]> {
  try {
    const { metadata } = await sdkCore.resolveFileMetadata(fileMetaIpnsName, folderKey, ctx);
    const cids: CapturedCid[] = [];
    if (metadata.cid) cids.push({ cid: metadata.cid, size: metadata.size ?? 0 });
    for (const v of metadata.versions ?? []) {
      if (v.cid) cids.push({ cid: v.cid, size: v.size ?? 0 });
    }
    return cids;
  } catch (err) {
    console.warn(
      `[CipherBox] bin: could not capture content CIDs for file ${fileMetaIpnsName} (skipping):`,
      err instanceof Error ? err.message : err
    );
    return [];
  }
}

/**
 * Recursively walk a deleted folder subtree, collecting every node's IPNS name
 * and every descendant file's content + version CIDs.
 *
 * FAIL-CLOSED for structure (locked): if a folder's metadata cannot be resolved
 * or decrypted, the whole walk THROWS — addToBin must then abort the delete
 * rather than half-revoke / partially unpin. This is what guarantees the share
 * set is complete before the destructive folder mutation. (An individual file's
 * CID capture is best-effort via captureFileCids and never throws.)
 *
 * Any subfolder folderKey this function unwraps is zeroized in `finally` — it
 * owns those buffers. The caller-owned `folderKey` passed in is never zeroed here.
 *
 * A `visited` set guards against cycles/diamonds in client-supplied (decryptable,
 * corruption-influenceable) folder metadata.
 */
async function walkDeletedSubtree(params: {
  folderIpnsName: string;
  folderKey: Uint8Array;
  userPrivateKey: Uint8Array;
  ctx: SdkContext;
  acc?: SubtreeWalkResult;
  visited?: Set<string>;
}): Promise<SubtreeWalkResult> {
  const acc = params.acc ?? { ipnsNames: [], descendantCids: [] };
  const visited = params.visited ?? new Set<string>();

  if (visited.has(params.folderIpnsName)) return acc;
  visited.add(params.folderIpnsName);
  acc.ipnsNames.push(params.folderIpnsName);

  // FAIL-CLOSED: a null/throwing resolve means we cannot enumerate this folder's
  // structure, so we cannot guarantee a complete share set. Abort.
  let children;
  try {
    const result = await sdkCore.loadFolderMetadata({
      ipnsName: params.folderIpnsName,
      folderKey: params.folderKey,
      ctx: params.ctx,
    });
    if (!result) {
      throw new Error(
        `Cannot enumerate deleted subtree: folder ${params.folderIpnsName} did not resolve`
      );
    }
    children = result.metadata.children;
  } catch (err) {
    throw err instanceof Error
      ? err
      : new Error(`Cannot enumerate deleted subtree for ${params.folderIpnsName}`, { cause: err });
  }

  for (const child of children) {
    if (child.type === 'file') {
      const fp = child as FilePointer;
      acc.ipnsNames.push(fp.fileMetaIpnsName);
      // Best-effort per-file CID capture (decrypt with THIS folder's key).
      const cids = await captureFileCids(fp.fileMetaIpnsName, params.folderKey, params.ctx);
      acc.descendantCids.push(...cids);
    } else if (child.type === 'folder') {
      const entry = child as FolderEntry;
      if (visited.has(entry.ipnsName)) continue;
      let childFolderKey: Uint8Array | undefined;
      try {
        childFolderKey = await unwrapKey(
          hexToBytes(entry.folderKeyEncrypted),
          params.userPrivateKey
        );
        await walkDeletedSubtree({
          folderIpnsName: entry.ipnsName,
          folderKey: childFolderKey,
          userPrivateKey: params.userPrivateKey,
          ctx: params.ctx,
          acc,
          visited,
        });
      } finally {
        // Zero only the key buffer this frame unwrapped/owns.
        if (childFolderKey) clearBytes(childFolderKey);
      }
    }
  }

  return acc;
}

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
}): Promise<{ removedItem: FolderChild; updatedBinState: BinState }> {
  const folder = params.folderTree.get(params.folderIpnsName);
  if (!folder) throw new Error('Folder not loaded');

  // 0. Pre-compute the removed item WITHOUT mutating folder state yet, so the
  //    fail-closed walk + revoke can run before any destructive publish.
  const baseChildren = [...folder.children];
  const { updatedChildren, removedItem } = sdkCore.deleteFromFolder({
    children: folder.children,
    childId: params.childId,
  });

  const isFile = removedItem.type === 'file';

  // 1. Collect the deleted subtree: every node's ipnsName (for share revocation)
  //    and every descendant content/version CID (for unpin on empty-bin). For a
  //    single file this is just its own fileMetaIpnsName + its own CIDs; for a
  //    folder we walk the whole subtree (FAIL-CLOSED on unreadable structure).
  let collectedIpnsNames: string[];
  let descendantCids: Array<{ cid: string; size: number }> | undefined;
  let fileContentCid: string | undefined;
  let fileContentSize: number | undefined;
  let fileVersionCids: Array<{ cid: string; size: number }> | undefined;

  if (isFile) {
    const fp = removedItem as FilePointer;
    collectedIpnsNames = [fp.fileMetaIpnsName];
    // Best-effort capture of the file's own content + version CIDs.
    const cids = await captureFileCids(fp.fileMetaIpnsName, folder.folderKey, params.binCtx.ctx);
    if (cids.length > 0) {
      fileContentCid = cids[0].cid;
      fileContentSize = cids[0].size;
      const versionCids = cids.slice(1);
      if (versionCids.length > 0) fileVersionCids = versionCids;
    }
  } else {
    const fe = removedItem as FolderEntry;
    // Unwrap the deleted folder's own key, then walk. The walk THROWS if any
    // descendant folder can't be enumerated — abort before the folder mutation.
    let deletedFolderKey: Uint8Array | undefined;
    try {
      deletedFolderKey = await unwrapKey(
        hexToBytes(fe.folderKeyEncrypted),
        params.binCtx.userPrivateKey
      );
      const walk = await walkDeletedSubtree({
        folderIpnsName: fe.ipnsName,
        folderKey: deletedFolderKey,
        userPrivateKey: params.binCtx.userPrivateKey,
        ctx: params.binCtx.ctx,
      });
      collectedIpnsNames = walk.ipnsNames;
      if (walk.descendantCids.length > 0) descendantCids = walk.descendantCids;
    } finally {
      if (deletedFolderKey) clearBytes(deletedFolderKey);
    }
  }

  // 2. FAIL-CLOSED share revocation — MUST precede the destructive folder
  //    mutation. If it ultimately fails (after its own retries), abort the whole
  //    delete: the item stays in the folder and no shares are stranded-active on
  //    deleted content.
  if (params.revokeSharesForItemsFn) {
    await shareOps.revokeSharesForItems({
      ipnsNames: collectedIpnsNames,
      revokeFn: params.revokeSharesForItemsFn,
    });
  }

  // Capture the source folder's folderKey (the key the file's FileMetadata is
  // encrypted under) wrapped for the vault, so restore can re-encrypt to any
  // destination later even if this parent folder is gone by then. Files only —
  // a restored folder carries its own folderKey in its FolderEntry. Computed
  // BEFORE the publish so a wrapKey failure aborts before any folder/bin
  // mutation, avoiding a split state where the file is removed from the folder
  // but never recorded in the bin.
  const originalFolderKeyEncrypted = isFile
    ? bytesToHex(await wrapKey(folder.folderKey, params.binCtx.userPublicKey))
    : undefined;

  // 3. Publish updated folder metadata (destructive — only after revoke succeeded)
  const { newSequenceNumber, publishedChildren } = await sdkCore.updateFolderMetadataAndPublish({
    children: updatedChildren,
    baseChildren,
    folderKey: folder.folderKey,
    ipnsPrivateKey: folder.ipnsKeypair.privateKey,
    ipnsName: params.folderIpnsName,
    sequenceNumber: folder.sequenceNumber,
    ctx: params.binCtx.ctx,
  });

  // 4. Update folder state — adopt merged published set (CR-01)
  folder.children = publishedChildren;
  folder.sequenceNumber = newSequenceNumber;
  folder.lastLoadedAt = Date.now();
  params.folderTree.set(params.folderIpnsName, folder);

  // 5. Build bin entry with the captured CIDs (so empty-bin/permanent-delete can
  //    unpin the content + versions + descendant subtree).
  const entry: BinEntry = {
    id: crypto.randomUUID(),
    itemType: isFile ? 'file' : 'folder',
    name: removedItem.name,
    originalParentIpnsName: params.folderIpnsName,
    originalPath: params.parentPath,
    deletedAt: Date.now(),
    size: 0,
    mimeType: '',
    contentCid: fileContentCid,
    contentSize: fileContentSize,
    versionCids: fileVersionCids,
    descendantCids,
    filePointer: isFile ? (removedItem as FilePointer) : undefined,
    folderEntry: !isFile ? (removedItem as FolderEntry) : undefined,
    originalFolderKeyEncrypted,
  };

  // 6. Update bin metadata and publish
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

  // A retry of a partially-applied restore (the bin entry survives a step-5b /
  // step-6 failure) can find this child already listed in the target from the prior
  // attempt's publish. Drop any prior copy by id so the restore is idempotent —
  // re-running REPLACES rather than duplicates the listing — and exclude it from the
  // name-collision check so the file isn't spuriously renamed against itself. The
  // no-conflict publish path doesn't dedup by id (only the 409 merge does), so a
  // same-id duplicate appended here would otherwise persist.
  const targetChildrenSansChild = targetFolder.children.filter((c) => c.id !== child.id);

  // Handle name collisions (against other entries only)
  const existingNames = new Set(targetChildrenSansChild.map((c) => c.name));
  if (existingNames.has(child.name)) {
    let newName = `${child.name} (restored)`;
    let counter = 2;
    while (existingNames.has(newName)) {
      newName = `${child.name} (restored ${counter})`;
      counter++;
    }
    child = { ...child, name: newName };
  }

  // 3b. Decide whether this restore must re-encrypt the file's FileMetadata to
  // the target folderKey: only for a FILE restored to a DIFFERENT folder than its
  // original parent. The record is AES-256-GCM sealed with the parent folderKey,
  // and addToBin stores the FilePointer verbatim without re-keying; restoring to a
  // folder with a different folderKey without re-encrypting would make the file
  // undecryptable (CryptoError: Decryption failed) — the same class of bug as
  // moveItem. Restoring in place (target === original parent, the default UI flow)
  // leaves the key unchanged, so no re-encrypt is needed.
  //
  // Validate the preconditions NOW, before publishing, so a restore that is
  // guaranteed to fail (missing file IPNS key, or a legacy entry whose source key
  // can't be recovered) aborts cleanly without leaving an undecryptable listing in
  // the target. The actual re-key — unwrap + network resolve/publish — runs AFTER
  // the target folder is durably published (step 5b), mirroring moveItem: the
  // metadata is only re-keyed once the target listing is durable, so at every
  // intermediate failure the file stays readable from somewhere that lists it under
  // the matching key (the bin, by the source key, before the re-key; the target, by
  // the target key, after it) — never readable from neither.
  const mustReencrypt =
    entry.itemType === 'file' &&
    !!entry.filePointer &&
    params.targetFolderIpnsName !== entry.originalParentIpnsName;
  if (mustReencrypt) {
    if (!entry.filePointer!.ipnsPrivateKeyEncrypted) {
      throw new Error('Cannot re-encrypt file metadata on restore: missing file IPNS key');
    }
    // Source key = the folderKey the FileMetadata is currently sealed under.
    // Recoverable from the key captured at delete time (works even if the original
    // parent is gone), or — for legacy entries created before that capture — from
    // the still-loaded original parent folder.
    if (!entry.originalFolderKeyEncrypted && !params.folderTree.get(entry.originalParentIpnsName)) {
      throw new Error(
        'Original parent folder must be loaded to restore a legacy file to a different folder'
      );
    }
  }

  const baseChildren = [...targetFolder.children];
  const updatedFolderChildren = [...targetChildrenSansChild, child];

  // 4. Publish target folder first (add-before-remove): the file is listed in the
  //    target while still recorded in the bin, so it is never lost mid-restore.
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

  // 5b. Re-key the FileMetadata to the target folderKey, now that the target
  //     listing is durable (see step 3b). Idempotent via
  //     reencryptFileMetadataForFolderChange: a retry after a partial failure that
  //     already re-keyed the record completes cleanly instead of throwing.
  if (mustReencrypt) {
    // Only freshly-unwrapped key material is cleared in `finally` — never the
    // shared folderTree key from the legacy fallback, which the tree still owns.
    let unwrappedSourceFolderKey: Uint8Array | undefined;
    let fileIpnsPrivateKey: Uint8Array | undefined;
    try {
      // Both guaranteed by the precondition check above; re-narrowed here for the
      // type-checker and as defense in depth.
      const filePointer = entry.filePointer;
      const ipnsPrivateKeyEncrypted = filePointer?.ipnsPrivateKeyEncrypted;
      if (!filePointer || !ipnsPrivateKeyEncrypted) {
        throw new Error('Cannot re-encrypt file metadata on restore: missing file IPNS key');
      }

      let sourceFolderKey: Uint8Array;
      if (entry.originalFolderKeyEncrypted) {
        unwrappedSourceFolderKey = await unwrapKey(
          hexToBytes(entry.originalFolderKeyEncrypted),
          params.binCtx.userPrivateKey
        );
        sourceFolderKey = unwrappedSourceFolderKey;
      } else {
        const sourceFolder = params.folderTree.get(entry.originalParentIpnsName);
        if (!sourceFolder) {
          throw new Error(
            'Original parent folder must be loaded to restore a legacy file to a different folder'
          );
        }
        sourceFolderKey = sourceFolder.folderKey;
      }

      fileIpnsPrivateKey = await unwrapKey(
        hexToBytes(ipnsPrivateKeyEncrypted),
        params.binCtx.userPrivateKey
      );
      await reencryptFileMetadataForFolderChange({
        fileMetaIpnsName: filePointer.fileMetaIpnsName,
        fileIpnsPrivateKey,
        sourceFolderKey,
        destFolderKey: targetFolder.folderKey,
        ctx: params.binCtx.ctx,
      });
    } finally {
      if (unwrappedSourceFolderKey) clearBytes(unwrappedSourceFolderKey);
      if (fileIpnsPrivateKey) clearBytes(fileIpnsPrivateKey);
    }
  }

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
