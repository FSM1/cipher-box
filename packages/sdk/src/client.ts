/**
 * @cipherbox/sdk - CipherBoxClient
 *
 * Stateful client orchestrating folder CRUD, file upload/download,
 * and event-driven change notification. Wraps @cipherbox/sdk-core
 * stateless functions with internal state management (FolderTree, KeyCache).
 *
 * Design principles:
 * - Zero React/Zustand/browser dependencies
 * - All state flows through typed events (SdkEvent)
 * - Operations are wrapped with withOperation() for consistent
 *   start/end/error event emission
 * - Key material is cleared on destroy()
 */

import type { SdkContext, ProgressCallback, DownloadProgressCallback } from '@cipherbox/sdk-core';
import type { PinningProvider, ExternalEncryptFn } from '@cipherbox/sdk-core';
import type { UploadResult } from '@cipherbox/sdk-core';
import * as sdkCore from '@cipherbox/sdk-core';
import { selectEncryptionMode } from '@cipherbox/sdk-core';
import {
  createAxiosInstance,
  ipnsControllerUnenrollBatch,
  sharesControllerRevokeForItems,
} from '@cipherbox/api-client';
import { clearBytes, unwrapKey, hexToBytes } from '@cipherbox/crypto';
import pLimit from 'p-limit';
import type { BinEntry, SealedChildRef, PublishedNode } from '@cipherbox/core';
import { sealChildReadKey, unsealChildReadKey } from '@cipherbox/core';
import type { CipherBoxClientConfig, FolderState, SharedFolderState } from './types';
import { SdkEventEmitter, type SdkEvent, type SdkEventHandler } from './events';
import { FolderTree } from './state/folder-tree';
import { SharedFolderTree } from './state/shared-folder-tree';
import { KeyCache } from './state/key-cache';
import * as binOps from './bin';
import type { BinState } from './bin';
import * as shareOps from './share';

/** Maximum concurrent encrypt+pin operations for batch uploads. */
const UPLOAD_CONCURRENCY = 3;

/**
 * Maximum concurrent on-demand IPNS subtree collections for fire-and-forget
 * unenroll. Bounds the request fan-out when emptying/purging a bin with many
 * top-level entries (WR-04). Each collection still walks its own subtree
 * sequentially, so this caps the number of subtrees fetched in parallel.
 */
const UNENROLL_COLLECT_CONCURRENCY = 8;

/** Thrown when a bin operation is attempted before loadBin() has been called. */
export class BinNotLoadedError extends Error {
  constructor() {
    super('Bin not loaded');
    this.name = 'BinNotLoadedError';
  }
}

export class CipherBoxClient {
  private config: CipherBoxClientConfig;
  private ctx: SdkContext;
  private emitter: SdkEventEmitter;
  private folderTree: FolderTree;
  /**
   * Sibling tree owning SHARED-folder state, keyed by `shareId` (NOT `ipnsName`).
   * Shared folders carry a distinct SharedWriteContext and can collide on
   * `ipnsName`, so they live in their own map (D REQ-3, A4).
   */
  private sharedFolderTree: SharedFolderTree;
  private keyCache: KeyCache;
  private binState: BinState | null = null;
  /** BYO-IPFS external pinning provider (null when mode is 'cipherbox') */
  private externalProvider: PinningProvider | null = null;
  /** Internal copies of key material — zeroed on destroy() without affecting caller buffers */
  private internalVaultKeypair: { publicKey: Uint8Array; privateKey: Uint8Array };
  private internalRootFolderKey: Uint8Array;
  /**
   * Internal copy of the root IPNS signing keypair, or null when not configured.
   * Enables self-bootstrapping the folder tree from root (see ensureFolderLoaded).
   */
  private internalRootIpnsKeypair: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null;

  constructor(config: CipherBoxClientConfig) {
    // Defensive copy of key material so destroy() only zeroes our copies
    this.internalVaultKeypair = {
      publicKey: new Uint8Array(config.vaultKeypair.publicKey),
      privateKey: new Uint8Array(config.vaultKeypair.privateKey),
    };
    this.internalRootFolderKey = new Uint8Array(config.rootFolderKey);
    if (config.rootIpnsKeypair) {
      this.internalRootIpnsKeypair = {
        publicKey: new Uint8Array(config.rootIpnsKeypair.publicKey),
        privateKey: new Uint8Array(config.rootIpnsKeypair.privateKey),
      };
    }
    this.config = {
      ...config,
      vaultKeypair: this.internalVaultKeypair,
      rootFolderKey: this.internalRootFolderKey,
      rootIpnsKeypair: this.internalRootIpnsKeypair ?? undefined,
    };
    const axiosInstance =
      config.axiosInstance ??
      createAxiosInstance({
        baseUrl: config.apiUrl,
        getAccessToken: config.getAccessToken,
        defaultHeaders: config.defaultHeaders,
      });
    this.ctx = {
      apiUrl: config.apiUrl,
      getAccessToken: config.getAccessToken,
      axiosInstance,
    };
    this.emitter = new SdkEventEmitter();
    this.folderTree = new FolderTree();
    this.sharedFolderTree = new SharedFolderTree();
    this.keyCache = new KeyCache();

    // Initialize BYO pinning provider if configured
    if (config.pinningConfig?.mode !== 'cipherbox' && config.pinningConfig?.externalProvider) {
      const ext = config.pinningConfig.externalProvider;
      if (ext.protocol === 'kubo') {
        this.externalProvider = new sdkCore.KuboProvider(ext.endpoint, ext.authToken);
      } else if (ext.protocol === 'pinata') {
        this.externalProvider = new sdkCore.PinataProvider(ext.endpoint, ext.authToken);
      } else {
        this.externalProvider = new sdkCore.PsaProvider(ext.endpoint, ext.authToken);
      }
    }
  }

  // ---- Event subscription ----

  /** Subscribe to SDK events. Returns an unsubscribe function. */
  on(handler: SdkEventHandler): () => void {
    return this.emitter.on(handler);
  }

  /** Unsubscribe a previously registered handler. */
  off(handler: SdkEventHandler): void {
    this.emitter.off(handler);
  }

  // ---- Lifecycle ----

  /**
   * Fire-and-forget IPNS unenrollment for deleted items.
   * Collects IPNS names from removed items and calls the batch unenroll API.
   * Failures are logged but never block the caller.
   */
  private fireAndForgetUnenroll(ipnsNames: string[]): void {
    if (ipnsNames.length === 0) return;

    const apiOptions = this.ctx.axiosInstance
      ? { _axiosInstance: this.ctx.axiosInstance }
      : undefined;

    // Chunk to respect API batch limit (max 200 per call)
    const BATCH_SIZE = 200;
    for (let i = 0; i < ipnsNames.length; i += BATCH_SIZE) {
      const chunk = ipnsNames.slice(i, i + BATCH_SIZE);
      ipnsControllerUnenrollBatch({ ipnsNames: chunk }, apiOptions).catch((err: unknown) => {
        console.warn(
          `[CipherBox] IPNS unenroll failed for ${chunk.length} name(s):`,
          err instanceof Error ? err.message : err
        );
      });
    }
  }

  /**
   * Issue an authed POST /shares/revoke-for-items for the deleted subtree's IPNS
   * names. Unlike unenroll, this is AWAITED and fail-closed by addToBin: if it
   * throws, the delete aborts before the destructive folder mutation, so a
   * still-shared content CID can never be orphaned by the eventual empty-bin unpin.
   */
  private async revokeSharesForItems(ipnsNames: string[]): Promise<void> {
    if (ipnsNames.length === 0) return;
    const apiOptions = this.ctx.axiosInstance
      ? { _axiosInstance: this.ctx.axiosInstance }
      : undefined;
    await sharesControllerRevokeForItems({ ipnsNames }, apiOptions);
  }

  /**
   * Fire-and-forget IPNS unenrollment for a set of bin entries.
   * Collects each entry's subtree IPNS names with a bounded concurrency limit
   * (WR-04), then dispatches the flattened batch. Failures are logged but never
   * block the caller.
   */
  private fireAndForgetUnenrollEntries(entries: BinEntry[]): void {
    const collectLimit = pLimit(UNENROLL_COLLECT_CONCURRENCY);
    Promise.all(entries.map((entry) => collectLimit(() => this.collectBinEntryIpnsNames(entry))))
      .then((nameArrays) => this.fireAndForgetUnenroll(nameArrays.flat()))
      .catch((err) => console.warn('[CipherBox] IPNS unenroll collection failed:', err));
  }

  /**
   * Extract IPNS names from a removed SealedChildRef (file or folder subtree).
   *
   * @stub phase 65 (bin re-link): SealedChildRef has no type discriminant; the
   * phase-65 subtree walk will traverse Node children via the read-chain.
   */
  private async collectRemovedItemIpnsNames(item: SealedChildRef): Promise<string[]> {
    void item;
    throw new Error('not implemented — phase 65 (bin re-link: subtree IPNS collect)');
  }

  /**
   * Extract IPNS names from a BinEntry (node ref and/or folder subtree).
   *
   * @stub phase 65 (bin re-link): BinEntry.filePointer / .folderEntry removed;
   * phase-65 implementation reads from BinEntry.nodeRef instead.
   */
  private async collectBinEntryIpnsNames(entry: BinEntry): Promise<string[]> {
    void entry;
    throw new Error('not implemented — phase 65 (bin re-link: subtree IPNS collect)');
  }

  /**
   * Destroy the client, clearing all sensitive state.
   * After calling destroy(), the client instance should not be reused.
   */
  destroy(): void {
    this.folderTree.clear();
    this.sharedFolderTree.clear();
    this.keyCache.clear();
    this.emitter.removeAll();
    // Zero internal key copies (defense-in-depth; JS GC may retain copies)
    // Only zeroes our copies, not the caller-provided buffers
    this.internalVaultKeypair.privateKey.fill(0);
    this.internalVaultKeypair.publicKey.fill(0);
    this.internalRootFolderKey.fill(0);
    if (this.internalRootIpnsKeypair) {
      this.internalRootIpnsKeypair.privateKey.fill(0);
      this.internalRootIpnsKeypair.publicKey.fill(0);
    }
    this.binState = null;
  }

  /**
   * Check if the SDK already has state for a folder.
   *
   * @param ipnsName - Folder's IPNS name
   * @returns true if the folder is registered in the SDK's FolderTree
   */
  hasFolder(ipnsName: string): boolean {
    return this.folderTree.has(ipnsName);
  }

  /**
   * Get the current sequence number for a folder in the SDK's internal state.
   * Returns undefined if the folder is not registered.
   */
  getFolderSequenceNumber(ipnsName: string): bigint | undefined {
    return this.folderTree.get(ipnsName)?.sequenceNumber;
  }

  /**
   * Get the IPNS private key for a folder in the SDK's internal state.
   * Returns undefined if the folder is not registered or has no key.
   *
   * SDK-created folders store their IPNS keys internally (in folderTree),
   * not in the Zustand store, so this is their authoritative source.
   */
  getFolderIpnsPrivateKey(ipnsName: string): Uint8Array | undefined {
    const key = this.folderTree.get(ipnsName)?.ipnsKeypair?.privateKey;
    // Return a copy so callers can't mutate internal state
    return key && key.length > 0 ? new Uint8Array(key) : undefined;
  }

  /**
   * Register an externally-loaded folder into the SDK's internal state.
   *
   * Used when folder metadata is loaded outside the SDK (e.g., by a navigation
   * hook) but the SDK needs to know about the folder for mutation operations
   * (create, rename, move, delete, upload).
   *
   * This is a bridge method for gradual SDK adoption -- eventually all folder
   * loading should go through client.loadFolder().
   *
   * @param ipnsName - Folder's IPNS name
   * @param folderKey - Decrypted AES-256 folder key
   * @param ipnsKeypair - Ed25519 keypair for IPNS signing
   * @param children - Current folder children
   * @param sequenceNumber - Current IPNS sequence number
   * @param nodeId - UUID of the folder's underlying Node (D-06). Callers who know the
   *   UUID (e.g. after createSubfolder) should supply it. Omitting leaves an empty
   *   placeholder that will be filled by loadFolder; CRUD operations called before
   *   loadFolder will throw 'nodeId is required'.
   * @param nodeGeneration - Rotation counter of the folder's Node (D-06).
   */
  registerFolder(
    ipnsName: string,
    folderKey: Uint8Array,
    ipnsKeypair: { publicKey: Uint8Array; privateKey: Uint8Array },
    children: SealedChildRef[],
    sequenceNumber: bigint,
    nodeId?: string,
    nodeGeneration?: number
  ): void {
    // Defensive copy so destroy() -> folderTree.clear() doesn't zero caller buffers
    this.folderTree.set(ipnsName, {
      ipnsName,
      folderKey: new Uint8Array(folderKey),
      ipnsKeypair: {
        publicKey: new Uint8Array(ipnsKeypair.publicKey),
        privateKey: new Uint8Array(ipnsKeypair.privateKey),
      },
      sequenceNumber,
      children,
      metadata: null,
      lastLoadedAt: Date.now(),
      // D-06: nodeId/nodeGeneration required for AAD-stable CRUD operations.
      // Empty string placeholder if caller omits — loadFolder will fill it.
      nodeId: nodeId ?? '',
      nodeGeneration: nodeGeneration ?? 0,
    });
  }

  // ---- Internal state access (for bin/share modules) ----

  /** @internal Get the folder tree for bin/share operations */
  getFolderTree(): FolderTree {
    return this.folderTree;
  }

  /** @internal Get the SDK context */
  getContext(): SdkContext {
    return this.ctx;
  }

  /** @internal Get the client config */
  getConfig(): CipherBoxClientConfig {
    return this.config;
  }

  /** @internal Emit an event (used by bin/share modules) */
  emitEvent(event: SdkEvent): void {
    this.emitter.emit(event);
  }

  // ---- Folder operations ----

  /**
   * Load a folder's metadata from IPNS.
   *
   * Resolves the folder's IPNS record, decrypts metadata, stores state
   * internally, and emits a 'folder:loaded' event.
   *
   * @param ipnsName - Folder's IPNS name
   * @param folderKey - Decrypted AES-256 folder key
   * @param ipnsKeypair - Ed25519 keypair for IPNS signing
   * @returns The loaded folder state, or null if IPNS record not found
   */
  async loadFolder(
    ipnsName: string,
    folderKey: Uint8Array,
    ipnsKeypair: { publicKey: Uint8Array; privateKey: Uint8Array }
  ): Promise<FolderState | null> {
    return this.withOperation('loadFolder', async () => {
      const result = await sdkCore.loadFolderMetadata({
        ipnsName,
        folderKey,
        ctx: this.ctx,
      });

      if (!result) return null;

      // IPNS reads lag a just-written sequence (#489 sequence-as-clock invariant).
      // Never overwrite a fresher in-memory entry with a stale IPNS snapshot.
      const existing = this.folderTree.get(ipnsName);
      if (existing && existing.sequenceNumber >= result.sequenceNumber) {
        this.emitter.emit({
          type: 'folder:loaded',
          folderId: ipnsName,
          ipnsName,
          children: existing.children,
          sequenceNumber: existing.sequenceNumber,
        });
        return existing;
      }

      const state: FolderState = {
        ipnsName,
        folderKey,
        ipnsKeypair,
        sequenceNumber: result.sequenceNumber,
        children: result.metadata.children ?? [],
        metadata: result.metadata,
        lastLoadedAt: Date.now(),
        // D-06: populate from the sealed Node's plaintext envelope fields.
        nodeId: result.metadata.id,
        nodeGeneration: result.metadata.generation,
      };

      this.folderTree.set(ipnsName, state);

      this.emitter.emit({
        type: 'folder:loaded',
        folderId: ipnsName,
        ipnsName,
        children: result.metadata.children ?? [],
        sequenceNumber: result.sequenceNumber,
      });

      return state;
    });
  }

  /**
   * Ensure a folder is present in the internal folderTree, self-bootstrapping
   * from root if necessary.
   *
   * If the target is already loaded, returns it immediately. Otherwise — when a
   * root IPNS keypair was configured — walks the folder tree from root (DFS with
   * early exit), resolving each folder's metadata and unwrapping each subfolder's
   * `folderKeyEncrypted` / `ipnsPrivateKeyEncrypted` with the vault keypair, until
   * the target is registered. Every folder visited along the way is cached, so
   * later calls are cheap.
   *
   * Returns null when the client cannot self-bootstrap (no `rootIpnsKeypair`
   * configured) or the target is not reachable from root. Callers fall back to
   * their existing 'Folder not loaded' error on null, so behavior is unchanged
   * when self-bootstrap is unavailable. This dissolves the "Folder not loaded"
   * failure class that previously required consumers to pre-seed folderTree
   * before every folderTree-dependent operation.
   *
   * @param targetIpnsName - IPNS name of the folder to ensure is loaded
   * @returns The loaded FolderState, or null if it cannot be bootstrapped
   * @internal
   */
  /**
   * @stub phase 63 (navigation/read fan-out): SealedChildRef has no
   * folderKeyEncrypted / ipnsPrivateKeyEncrypted fields; the phase-63 DFS will
   * unseal the child readKey from SealedChildRef.readKeySealed using the parent
   * Node's readKey chain to derive per-folder keys.
   */
  async ensureFolderLoaded(targetIpnsName: string): Promise<FolderState | null> {
    void targetIpnsName;
    throw new Error('not implemented — phase 63 (navigation/read fan-out)');
  }

  /**
   * Resolve a folder from internal state, self-bootstrapping from root if needed.
   *
   * Returns the loaded FolderState or throws `${label} not loaded`. This is the
   * single chokepoint every folderTree-dependent mutation routes through, so the
   * get-or-self-load-or-throw contract lives in one place and a new method can't
   * silently forget the self-heal fallback.
   *
   * @param ipnsName - IPNS name of the required folder
   * @param label - Human label for the error (e.g. 'Parent folder', 'Source folder')
   */
  private async requireFolder(ipnsName: string, label = 'Folder'): Promise<FolderState> {
    const folder = this.folderTree.get(ipnsName) ?? (await this.ensureFolderLoaded(ipnsName));
    if (!folder) throw new Error(`${label} not loaded`);
    return folder;
  }

  /**
   * Create a new subfolder inside an existing folder.
   *
   * Generates IPNS keypair and folder key, wraps with user's public key,
   * adds folder entry to parent metadata, publishes parent IPNS record,
   * and publishes empty folder metadata for the new subfolder.
   *
   * @param parentIpnsName - IPNS name of the parent folder
   * @param name - Name for the new subfolder
   * @returns Created folder's UUID, IPNS name, folder key, and IPNS private key
   */
  /**
   * @stub phase 63 (navigation/read fan-out): createSubfolder now returns
   * { node: Node; ... } not { folder: FolderEntry; ... }. Phase 63 will seal
   * the new Node under the parent's write-body and emit a SealedChildRef for
   * the parent's updated children list.
   */
  async createFolder(
    parentIpnsName: string,
    name: string
  ): Promise<{ id: string; ipnsName: string; folderKey: Uint8Array; ipnsPrivateKey: Uint8Array }> {
    void parentIpnsName;
    void name;
    throw new Error('not implemented — phase 63 (create subfolder node)');
  }

  /**
   * Rename a child entry (folder or file) in a folder.
   *
   * Updates the name in the folder's metadata and publishes the change.
   *
   * @param folderIpnsName - IPNS name of the folder containing the item
   * @param childId - ID of the child to rename
   * @param newName - New name for the child
   */
  async renameItem(folderIpnsName: string, childId: string, newName: string): Promise<void> {
    return this.withOperation('renameItem', async () => {
      const folder = await this.requireFolder(folderIpnsName);

      // 1. Rename in metadata (pure operation)
      const baseChildren = [...folder.children];
      const { updatedChildren } = sdkCore.renameInFolder({
        children: folder.children,
        childId,
        newName,
      });

      // 2. Publish updated metadata
      const { newSequenceNumber, publishedChildren } = await sdkCore.updateFolderMetadataAndPublish(
        {
          children: updatedChildren,
          baseChildren,
          folderKey: folder.folderKey,
          ipnsPrivateKey: folder.ipnsKeypair.privateKey,
          ipnsName: folderIpnsName,
          sequenceNumber: folder.sequenceNumber,
          ctx: this.ctx,
          nodeId: folder.nodeId,
          nodeGeneration: folder.nodeGeneration,
        }
      );

      // 3. Update internal state — adopt merged published set (CR-01)
      folder.children = publishedChildren;
      folder.sequenceNumber = newSequenceNumber;
      folder.lastLoadedAt = Date.now();
      this.folderTree.set(folderIpnsName, folder);

      // 4. Emit update event
      this.emitter.emit({
        type: 'folder:updated',
        folderId: folderIpnsName,
        ipnsName: folderIpnsName,
        children: publishedChildren,
        sequenceNumber: newSequenceNumber,
      });
    });
  }

  /**
   * Move a child entry between two folders.
   *
   * Removes from source, adds to destination, publishes both IPNS records
   * (destination first for crash safety -- add-before-remove pattern).
   *
   * When the moved child is a FilePointer, re-encrypts the per-file IPNS metadata
   * record from the source folder key to the destination folder key. FileMetadata
   * is AES-256-GCM encrypted with the parent folder key at upload time; without
   * this step all decrypt operations (download, preview, edit) fail after a move.
   *
   * @param sourceIpnsName - IPNS name of the source folder
   * @param destIpnsName - IPNS name of the destination folder
   * @param childId - ID of the child to move
   */
  async moveItem(sourceIpnsName: string, destIpnsName: string, childId: string): Promise<void> {
    return this.withOperation('moveItem', async () => {
      // Direct folderTree lookup — both folders must already be loaded for a move
      // (ensureFolderLoaded is wired in phase 63 navigation; moveItem does not auto-load)
      const sourceFolder = this.folderTree.get(sourceIpnsName);
      if (!sourceFolder) throw new Error('Source folder not loaded');
      const destFolder = this.folderTree.get(destIpnsName);
      if (!destFolder) throw new Error('Destination folder not loaded');

      const baseSourceChildren = [...sourceFolder.children];
      const baseDestChildren = [...destFolder.children];

      // Pure link rewrite — zero re-encryption (READ-04)
      const { updatedSource, updatedDest, movedRef } = sdkCore.moveItem({
        sourceChildren: sourceFolder.children,
        destChildren: destFolder.children,
        childId,
      });

      // FLAG-63-U2: Re-seal the moved child's readKeySealed under the DEST parent readKey.
      // sdkCore.moveItem() is a pure link rewrite — the moved ref still carries a
      // readKeySealed blob bound to the SOURCE parent's readKey. Any reader navigating
      // the dest-folder IPNS path will fail AEAD verification unless we re-seal.
      //
      // The moved record is identified by its ipnsName (SealedChildRef carries no `id`
      // — NODE-03, design §2.2); `childId` is the caller-facing handle that
      // sdkCore.moveItem resolves to `movedRef`. Mutate the entry that is actually
      // present in `updatedDest` so the published record carries the re-sealed key.
      const destEntry = updatedDest.find((c) => c.ipnsName === movedRef.ipnsName);
      if (!destEntry) {
        throw new Error(
          `moveItem: moved child ${movedRef.ipnsName} not found in dest after link rewrite (FLAG-63-U2)`
        );
      }

      // Resolve the child's IPNS to read the plaintext id and kind from the PublishedNode
      // envelope. These are AAD inputs for sealChildReadKey / unsealChildReadKey.
      // id/kind are NEVER stored in SealedChildRef (NODE-03, design §2.2).
      const childIpnsRecord = await sdkCore.resolveIpnsRecord(movedRef.ipnsName, this.ctx);
      if (!childIpnsRecord) {
        throw new Error(
          `moveItem: cannot resolve child IPNS ${movedRef.ipnsName} for re-seal — record not found`
        );
      }
      const rawChildNode = await sdkCore.fetchFromIpfs(this.ctx, childIpnsRecord.cid);
      const childPub = JSON.parse(new TextDecoder().decode(rawChildNode)) as PublishedNode;

      // Recover the child readKey under the SOURCE parent key.
      // D-09: do NOT zero sourceFolder.folderKey (caller-owned buffer).
      const childReadKey = await unsealChildReadKey(
        destEntry.readKeySealed,
        sourceFolder.folderKey,
        childPub.id,
        childPub.kind,
        destEntry.generation
      );

      // Re-seal the child readKey under the DESTINATION parent key.
      // D-09: do NOT zero destFolder.folderKey (caller-owned buffer).
      try {
        destEntry.readKeySealed = await sealChildReadKey(
          childReadKey,
          destFolder.folderKey,
          childPub.id,
          childPub.kind,
          destEntry.generation // generation unchanged — no content re-encryption, no bump
        );
      } finally {
        // Zero the recovered child readKey on every exit path — engine-derived,
        // terminal-owned (D-09).
        childReadKey.fill(0);
      }

      // Publish updated source folder
      const { newSequenceNumber: srcSeq, publishedChildren: srcChildren } =
        await sdkCore.updateFolderMetadataAndPublish({
          children: updatedSource,
          baseChildren: baseSourceChildren,
          readKey: sourceFolder.folderKey,
          ipnsPrivateKey: sourceFolder.ipnsKeypair.privateKey,
          ipnsName: sourceIpnsName,
          sequenceNumber: sourceFolder.sequenceNumber,
          ctx: this.ctx,
          nodeId: sourceFolder.nodeId,
          nodeGeneration: sourceFolder.nodeGeneration,
        });

      sourceFolder.children = srcChildren;
      sourceFolder.sequenceNumber = srcSeq;
      this.folderTree.set(sourceIpnsName, sourceFolder);
      this.emitter.emit({
        type: 'folder:updated',
        folderId: sourceIpnsName,
        ipnsName: sourceIpnsName,
        children: srcChildren,
        sequenceNumber: srcSeq,
      });

      // Publish updated destination folder
      const { newSequenceNumber: dstSeq, publishedChildren: dstChildren } =
        await sdkCore.updateFolderMetadataAndPublish({
          children: updatedDest,
          baseChildren: baseDestChildren,
          readKey: destFolder.folderKey,
          ipnsPrivateKey: destFolder.ipnsKeypair.privateKey,
          ipnsName: destIpnsName,
          sequenceNumber: destFolder.sequenceNumber,
          ctx: this.ctx,
          nodeId: destFolder.nodeId,
          nodeGeneration: destFolder.nodeGeneration,
        });

      destFolder.children = dstChildren;
      destFolder.sequenceNumber = dstSeq;
      this.folderTree.set(destIpnsName, destFolder);
      this.emitter.emit({
        type: 'folder:updated',
        folderId: destIpnsName,
        ipnsName: destIpnsName,
        children: dstChildren,
        sequenceNumber: dstSeq,
      });
    });
  }

  /**
   * Delete a child entry from a folder's metadata.
   *
   * This is a simple metadata delete -- it does NOT move to bin.
   * Use deleteToBin() for soft-delete with bin support.
   *
   * @param folderIpnsName - IPNS name of the folder containing the item
   * @param childId - ID of the child to delete
   * @returns The removed child entry
   */
  async deleteItem(
    folderIpnsName: string,
    childId: string
  ): Promise<{ removedItem: SealedChildRef }> {
    return this.withOperation('deleteItem', async () => {
      const folder = await this.requireFolder(folderIpnsName);

      // 1. Remove from metadata (pure operation)
      const baseChildren = [...folder.children];
      const { updatedChildren, removedItem } = sdkCore.deleteFromFolder({
        children: folder.children,
        childId,
      });

      // 2. Publish updated metadata
      const { newSequenceNumber, publishedChildren } = await sdkCore.updateFolderMetadataAndPublish(
        {
          children: updatedChildren,
          baseChildren,
          folderKey: folder.folderKey,
          ipnsPrivateKey: folder.ipnsKeypair.privateKey,
          ipnsName: folderIpnsName,
          sequenceNumber: folder.sequenceNumber,
          ctx: this.ctx,
          nodeId: folder.nodeId,
          nodeGeneration: folder.nodeGeneration,
        }
      );

      // 3. Update internal state — adopt merged published set (CR-01)
      folder.children = publishedChildren;
      folder.sequenceNumber = newSequenceNumber;
      folder.lastLoadedAt = Date.now();
      this.folderTree.set(folderIpnsName, folder);

      // 4. Emit update event
      this.emitter.emit({
        type: 'folder:updated',
        folderId: folderIpnsName,
        ipnsName: folderIpnsName,
        children: publishedChildren,
        sequenceNumber: newSequenceNumber,
      });

      // 5. Fire-and-forget IPNS unenrollment (resolve async collection then dispatch)
      this.collectRemovedItemIpnsNames(removedItem)
        .then((names) => this.fireAndForgetUnenroll(names))
        .catch((err) => console.warn('[CipherBox] IPNS unenroll collection failed:', err));

      return { removedItem };
    });
  }

  // ---- File operations ----

  /**
   * Upload a file to a folder.
   *
   * Encrypts the file, uploads to IPFS, creates per-file IPNS metadata,
   * adds a FilePointer to the parent folder's metadata, and publishes.
   *
   * @param folderIpnsName - IPNS name of the target folder
   * @param data - Raw file content as Uint8Array
   * @param fileName - Display name for the file
   * @param mimeType - MIME type of the file
   * @param onProgress - Optional upload progress callback
   * @returns CID of the uploaded encrypted file
   */
  async uploadFile(
    folderIpnsName: string,
    data: Uint8Array,
    fileName: string,
    mimeType: string,
    onProgress?: ProgressCallback
  ): Promise<{ cid: string }> {
    return this.withOperation('uploadFile', async () => {
      const folder = await this.requireFolder(folderIpnsName);

      if (folder.children.some((child) => child.name === fileName)) {
        throw new Error('An item with this name already exists');
      }

      const fileId = crypto.randomUUID();

      // Build BYO-IPFS pinFn override when mode is not 'cipherbox'
      const mode = this.config.pinningConfig?.mode ?? 'cipherbox';
      let secondaryWarning: string | undefined;
      const pinFn =
        mode === 'cipherbox' || !this.externalProvider
          ? undefined
          : async (
              ctx: SdkContext,
              encData: Uint8Array,
              prog?: ProgressCallback
            ): Promise<{ cid: string; size: number }> => {
              const result = await this.pinWithMode(encData, ctx, prog);
              secondaryWarning = result.secondaryWarning;
              return { cid: result.cid, size: result.size };
            };

      // 1. Encrypt and upload file, create file metadata
      const encryptionMode = selectEncryptionMode(mimeType, data.length);
      const uploadResult = await sdkCore.uploadFile({
        data,
        fileId,
        mimeType,
        folderKey: folder.folderKey,
        userPublicKey: this.config.vaultKeypair.publicKey,
        ctx: this.ctx,
        onProgress,
        teeKeys: this.config.teeKeys,
        pinFn,
        encryptionMode,
      });

      try {
        // 2. Add FilePointer to folder's children (seals child readKey under parent readKey — READ-03)
        const baseChildren = [...folder.children];
        const { updatedChildren } = await sdkCore.addFilePointerToFolder({
          children: folder.children,
          childReadKey: uploadResult.fileKey,
          parentReadKey: folder.folderKey,
          childId: fileId,
          childKind: 'file',
          childGeneration: 0,
          name: fileName,
          ipnsName: uploadResult.fileMetaIpnsName,
          versionFloor: 0n,
        });

        // 3. Concurrent: file IPNS batch publish + folder metadata update
        //    These two operations are independent -- no data dependency between them.
        //    Using Promise.allSettled to handle partial failures gracefully.
        const [batchResult, folderResult] = await Promise.allSettled([
          sdkCore.batchPublishIpnsRecords([uploadResult.ipnsRecord], this.ctx),
          sdkCore.updateFolderMetadataAndPublish({
            children: updatedChildren,
            baseChildren,
            folderKey: folder.folderKey,
            ipnsPrivateKey: folder.ipnsKeypair.privateKey,
            ipnsName: folderIpnsName,
            sequenceNumber: folder.sequenceNumber,
            ctx: this.ctx,
            nodeId: folder.nodeId,
            nodeGeneration: folder.nodeGeneration,
          }),
        ]);

        // Folder metadata update is critical -- must succeed for upload to be valid
        if (folderResult.status === 'rejected') {
          throw folderResult.reason;
        }

        // File IPNS batch publish failure is non-critical -- the FilePointer in
        // folder metadata is valid, and the file IPNS record will be created
        // on next publish attempt or TEE republish cycle
        // Note: if folder update fails but batch publish succeeded, an orphaned IPNS
        // record may exist. This is benign -- no FilePointer references it, and the
        // IPNS name will be reused on the next successful upload attempt.
        if (batchResult.status === 'rejected') {
          const batchError =
            batchResult.reason instanceof Error
              ? batchResult.reason
              : new Error(String(batchResult.reason));
          console.warn(
            '[SDK] File IPNS batch publish failed (non-critical, will retry on next publish):',
            batchError
          );
          this.emitter.emit({
            type: 'ipns:batchPublishFailed',
            ipnsNames: [uploadResult.ipnsRecord.ipnsName],
            error: batchError,
          });
        } else if (batchResult.value?.totalFailed > 0) {
          // Server accepted the request but reported partial failure for some records
          console.warn(
            `[SDK] File IPNS batch publish partially failed: ${batchResult.value.totalFailed} of ${batchResult.value.totalFailed + batchResult.value.totalSucceeded} records failed`
          );
          this.emitter.emit({
            type: 'ipns:batchPublishFailed',
            ipnsNames: [uploadResult.ipnsRecord.ipnsName],
            error: new Error(
              `Batch publish partial failure: ${batchResult.value.totalFailed} record(s) failed`
            ),
          });
        }

        const { newSequenceNumber, publishedChildren } = folderResult.value;

        // 4. Update internal state — adopt merged published set (CR-01)
        folder.children = publishedChildren;
        folder.sequenceNumber = newSequenceNumber;
        folder.lastLoadedAt = Date.now();
        this.folderTree.set(folderIpnsName, folder);

        // 5. Emit events
        this.emitter.emit({
          type: 'file:uploaded',
          folderId: folderIpnsName,
          fileName,
          cid: uploadResult.cid,
        });
        this.emitter.emit({
          type: 'folder:updated',
          folderId: folderIpnsName,
          ipnsName: folderIpnsName,
          children: publishedChildren,
          sequenceNumber: newSequenceNumber,
        });

        // 5b. Emit secondary pin warning for dual mode (non-blocking)
        if (secondaryWarning) {
          this.emitter.emit({
            type: 'pin:secondaryFailed',
            cid: uploadResult.cid,
            providerName:
              this.config.pinningConfig?.externalProvider?.providerName ?? 'external node',
            error: secondaryWarning,
          });
        }

        return { cid: uploadResult.cid };
      } finally {
        clearBytes(uploadResult.fileKey);
      }
    });
  }

  /**
   * Upload multiple files to a folder in parallel with a single folder publish.
   *
   * Runs encrypt+pin operations concurrently (max UPLOAD_CONCURRENCY slots),
   * collects results, re-reads folder metadata for stale-children mitigation,
   * and publishes all successful FilePointers in one atomic update.
   *
   * Pipeline-style: each concurrency slot does encrypt -> pin -> free, so
   * in-flight ciphertext and encryption/pinning work are bounded by
   * UPLOAD_CONCURRENCY. Overall memory usage can still include all
   * caller-provided file buffers in the `files` array; callers handling large
   * batches should stream or chunk inputs if end-to-end memory must be bounded.
   * Re-reads folder metadata before final publish to avoid stale-children overwrites.
   * Partial failures still publish successful files.
   */
  async uploadFiles(
    folderIpnsName: string,
    files: Array<{ data: Uint8Array; fileName: string; mimeType: string }>,
    callbacks?: {
      onFileProgress?: (fileName: string, percent: number) => void;
      onFileComplete?: (fileName: string) => void;
      onFileError?: (fileName: string, error: string) => void;
    },
    options?: {
      encryptFn?: ExternalEncryptFn;
      pinFn?: (
        ctx: SdkContext,
        data: Uint8Array,
        onProgress?: ProgressCallback
      ) => Promise<{ cid: string; size: number }>;
    }
  ): Promise<{
    successes: Array<{ fileName: string; cid: string }>;
    failures: Array<{ fileName: string; error: string }>;
  }> {
    return this.withOperation('uploadFiles', async () => {
      const folder = await this.requireFolder(folderIpnsName);

      // Build BYO-IPFS pinFn override (same pattern as uploadFile)
      const mode = this.config.pinningConfig?.mode ?? 'cipherbox';
      const pinFn =
        options?.pinFn ??
        (mode === 'cipherbox' || !this.externalProvider
          ? undefined
          : async (
              ctx: SdkContext,
              encData: Uint8Array,
              prog?: ProgressCallback
            ): Promise<{ cid: string; size: number }> => {
              const result = await this.pinWithMode(encData, ctx, prog);
              return { cid: result.cid, size: result.size };
            });

      // Create p-limit concurrency pool
      const limit = pLimit(UPLOAD_CONCURRENCY);

      type FileResult = {
        fileName: string;
        fileId: string;
        uploadResult: UploadResult;
      };

      // Run all files through the pool with Promise.allSettled
      const settled = await Promise.allSettled(
        files.map((file) =>
          limit(async () => {
            const fileId = crypto.randomUUID();
            const encryptionMode = selectEncryptionMode(file.mimeType, file.data.length);

            const uploadResult = await sdkCore.uploadFile({
              data: file.data,
              fileId,
              mimeType: file.mimeType,
              folderKey: folder.folderKey,
              userPublicKey: this.config.vaultKeypair.publicKey,
              ctx: this.ctx,
              onProgress: (percent) => callbacks?.onFileProgress?.(file.fileName, percent),
              teeKeys: this.config.teeKeys,
              pinFn,
              encryptionMode,
              encryptFn: options?.encryptFn,
            });

            callbacks?.onFileComplete?.(file.fileName);
            return { fileName: file.fileName, fileId, uploadResult } as FileResult;
          })
        )
      );

      // Partition results into successes and failures
      const successes: FileResult[] = [];
      const failures: Array<{ fileName: string; error: string }> = [];

      for (let i = 0; i < settled.length; i++) {
        const result = settled[i];
        const fileName = files[i].fileName;
        if (result.status === 'fulfilled') {
          successes.push(result.value);
        } else {
          const errorMsg =
            result.reason instanceof Error ? result.reason.message : String(result.reason);
          failures.push({ fileName, error: errorMsg });
          callbacks?.onFileError?.(fileName, errorMsg);
        }
      }

      // If no successes, emit event and return early
      if (successes.length === 0) {
        this.emitter.emit({
          type: 'files:batchUploaded',
          folderId: folderIpnsName,
          successes: [],
          failures: failures.map((f) => ({ fileName: f.fileName, error: f.error })),
        });
        return { successes: [], failures };
      }

      try {
        // Re-read folder metadata to mitigate stale-children race
        const freshFolder = await sdkCore.loadFolderMetadata({
          ipnsName: folderIpnsName,
          folderKey: folder.folderKey,
          ctx: this.ctx,
        });
        const initialChildren = freshFolder?.metadata.children ?? folder.children;
        const baseChildren = [...initialChildren];
        let mergedChildren = initialChildren;
        const freshSeq = freshFolder?.sequenceNumber ?? folder.sequenceNumber;

        // Add FilePointers for all successful uploads (skip collisions gracefully)
        const registeredSuccesses: FileResult[] = [];
        for (const success of successes) {
          try {
            const { updatedChildren } = await sdkCore.addFilePointerToFolder({
              children: mergedChildren,
              childReadKey: success.uploadResult.fileKey,
              parentReadKey: folder.folderKey,
              childId: success.fileId,
              childKind: 'file',
              childGeneration: 0,
              name: success.fileName,
              ipnsName: success.uploadResult.fileMetaIpnsName,
              versionFloor: 0n,
            });
            mergedChildren = updatedChildren;
            registeredSuccesses.push(success);
          } catch (err) {
            // Name collision from concurrent upload on another device — treat as failure
            const errorMsg = err instanceof Error ? err.message : String(err);
            failures.push({ fileName: success.fileName, error: errorMsg });
            callbacks?.onFileError?.(success.fileName, errorMsg);
          }
        }

        // If all registrations failed after collision handling, skip publish
        if (registeredSuccesses.length === 0) {
          this.emitter.emit({
            type: 'files:batchUploaded',
            folderId: folderIpnsName,
            successes: [],
            failures: failures.map((f) => ({ fileName: f.fileName, error: f.error })),
          });
          return { successes: [], failures };
        }

        // Single folder publish + batch IPNS publish (concurrent)
        const ipnsRecords = registeredSuccesses.map((s) => s.uploadResult.ipnsRecord);
        const [folderResult, batchResult] = await Promise.allSettled([
          sdkCore.updateFolderMetadataAndPublish({
            children: mergedChildren,
            baseChildren,
            folderKey: folder.folderKey,
            ipnsPrivateKey: folder.ipnsKeypair.privateKey,
            ipnsName: folderIpnsName,
            sequenceNumber: freshSeq,
            ctx: this.ctx,
            nodeId: folder.nodeId,
            nodeGeneration: folder.nodeGeneration,
          }),
          sdkCore.batchPublishIpnsRecords(ipnsRecords, this.ctx),
        ]);

        // Folder publish failure is critical -- must succeed
        if (folderResult.status === 'rejected') {
          throw folderResult.reason;
        }

        // Batch IPNS publish failure is non-critical (same pattern as uploadFile)
        if (batchResult.status === 'rejected') {
          const batchError =
            batchResult.reason instanceof Error
              ? batchResult.reason
              : new Error(String(batchResult.reason));
          console.warn(
            '[SDK] File IPNS batch publish failed (non-critical, will retry on next publish):',
            batchError
          );
          this.emitter.emit({
            type: 'ipns:batchPublishFailed',
            ipnsNames: ipnsRecords.map((r) => r.ipnsName),
            error: batchError,
          });
        } else if (batchResult.value?.totalFailed > 0) {
          console.warn(
            `[SDK] File IPNS batch publish partially failed: ${batchResult.value.totalFailed} of ${batchResult.value.totalFailed + batchResult.value.totalSucceeded} records failed`
          );
          this.emitter.emit({
            type: 'ipns:batchPublishFailed',
            ipnsNames: ipnsRecords.map((r) => r.ipnsName),
            error: new Error(
              `Batch publish partial failure: ${batchResult.value.totalFailed} record(s) failed`
            ),
          });
        }

        const { newSequenceNumber, publishedChildren } = folderResult.value;

        // Update internal state — adopt merged published set (CR-01)
        folder.children = publishedChildren;
        folder.sequenceNumber = newSequenceNumber;
        folder.lastLoadedAt = Date.now();
        this.folderTree.set(folderIpnsName, folder);

        // Emit events
        this.emitter.emit({
          type: 'files:batchUploaded',
          folderId: folderIpnsName,
          successes: registeredSuccesses.map((s) => ({
            fileName: s.fileName,
            cid: s.uploadResult.cid,
          })),
          failures,
        });
        this.emitter.emit({
          type: 'folder:updated',
          folderId: folderIpnsName,
          ipnsName: folderIpnsName,
          children: publishedChildren,
          sequenceNumber: newSequenceNumber,
        });

        return {
          successes: registeredSuccesses.map((s) => ({
            fileName: s.fileName,
            cid: s.uploadResult.cid,
          })),
          failures,
        };
      } finally {
        // Clear file keys for all uploads (including collision-failed ones)
        for (const success of successes) {
          clearBytes(success.uploadResult.fileKey);
        }
      }
    });
  }

  /**
   * Replace a file's content, owning the full publish + folderTree bookkeeping.
   *
   * Routes the web "file replace" path (formerly the `useFileOperations`
   * fire-and-forget "6b" block) through the client so the SDK `folderTree`
   * stays authoritative. Steps:
   *   1. Read the parent folder + sequence from `folderTree.get()` (authoritative
   *      SDK state) — throws 'Folder not loaded' if absent.
   *   2. Publish the file's per-IPNS metadata via sdk-core `updateFileMetadata`
   *      (CAS-published internally). Capture `prunedCids` for the caller to unpin.
   *   3. Touch the folder: snapshot `baseChildren`, bump the matching FilePointer's
   *      `modifiedAt` (and persist a migrated IPNS key if provided), then publish
   *      via `updateFolderMetadataAndPublish`.
   *   4. Adopt `publishedChildren` + `newSequenceNumber` into `folderTree`.
   *   5. Emit `folder:updated`.
   *
   * Per locked decision 2 the caller pre-resolves `fileIpnsPrivateKey` and
   * `currentMetadata` (web tier owns key resolution). This method does NOT zero
   * `fileIpnsPrivateKey` — sdk-core `updateFileMetadata` zeroes it in its own
   * finally on every exit path (T-47-01); the caller owns any additional lifecycle.
   *
   * @param parentIpnsName - IPNS name of the folder containing the file
   * @param fileId - ID of the file (FilePointer) to replace
   * @param fileData - Pre-resolved key + metadata + content updates
   * @returns Pruned version CIDs the caller should unpin
   */
  /**
   * @stub phase 65 (write-chain): FileMetadata replaced by NodeContent sealed in
   * the file Node's write-body; the file's IPNS record contains a sealed Node,
   * not a standalone FileMetadata blob. updateFileMetadata is stubbed in sdk-core.
   */
  async replaceFile(
    parentIpnsName: string,
    fileId: string,
    fileData: {
      fileIpnsPrivateKey: Uint8Array;
      currentMetadata: unknown;
      updates: unknown;
      createVersion: boolean;
      maxVersionsPerFile?: number;
      migratedIpnsPrivateKeyEncrypted?: string;
    }
  ): Promise<{ prunedCids: string[] }> {
    void parentIpnsName;
    void fileId;
    void fileData;
    throw new Error('not implemented — phase 65 (write-chain: replaceFile)');
  }

  /**
   * Restore a previous version of a file, owning publish + folderTree bookkeeping.
   *
   * Mirrors the web `useFileVersions.handleRestoreVersion` control flow, routed
   * through the client so `folderTree` stays authoritative:
   *   1. Read the parent folder from `folderTree.get()` — throws if absent.
   *   2. Publish the file's per-IPNS metadata via `updateFileMetadata` using the
   *      pre-resolved restored metadata (`updates`). Capture `prunedCids`.
   *   3. CONDITIONAL folder publish — only when `migratedIpnsPrivateKeyEncrypted`
   *      is provided (lazy IPNS-key migration): bump the FilePointer's
   *      `modifiedAt` + `ipnsPrivateKeyEncrypted`, publish, and adopt the result.
   *      Otherwise leave folder children + sequence unchanged (the file-only
   *      publish does not advance the folder sequence).
   *   4. Emit `folder:updated` reading back from `folderTree` so both branches
   *      emit a consistent snapshot.
   *
   * Per locked decision 2 the caller pre-resolves `fileIpnsPrivateKey`,
   * `currentMetadata`, and the restored `updates` (web tier owns the restore
   * service logic). This method does NOT zero `fileIpnsPrivateKey` —
   * `updateFileMetadata` owns zeroing (T-47-01).
   *
   * @param parentIpnsName - IPNS name of the folder containing the file
   * @param fileId - ID of the file (FilePointer) to restore
   * @param versionIndex - Index of the version being restored (caller-resolved)
   * @param params - Pre-resolved key + metadata + restored content updates
   * @returns Pruned version CIDs the caller should unpin
   */
  /**
   * @stub phase 65 (write-chain): VersionEntry replaces FileMetadata.versions[];
   * version restore will unseal a VersionEntry from NodeContent and publish an
   * updated Node via the write-chain. updateFileMetadata is stubbed in sdk-core.
   */
  async restoreFileVersion(
    parentIpnsName: string,
    fileId: string,
    versionIndex: number,
    params: {
      fileIpnsPrivateKey: Uint8Array;
      currentMetadata: unknown;
      updates: unknown;
      createVersion?: boolean;
      maxVersionsPerFile?: number;
      migratedIpnsPrivateKeyEncrypted?: string;
    }
  ): Promise<{ prunedCids: string[] }> {
    void parentIpnsName;
    void fileId;
    void versionIndex;
    void params;
    throw new Error('not implemented — phase 65 (write-chain: restoreFileVersion)');
  }

  /**
   * Delete a specific past version from a file's history, owning publish +
   * folderTree bookkeeping.
   *
   * Mirrors the web `useFileVersions.handleDeleteVersion` control flow. Same
   * five-step shape as {@link restoreFileVersion}: publish file metadata via
   * `updateFileMetadata`, conditional folder publish only on lazy IPNS-key
   * migration, then emit `folder:updated` from the folderTree snapshot.
   *
   * Per locked decision 2 the caller pre-resolves `fileIpnsPrivateKey`,
   * `currentMetadata`, the version-pruned `updates`, and the `deletedCid` (web
   * tier owns the delete service logic). This method does NOT zero
   * `fileIpnsPrivateKey` — `updateFileMetadata` owns zeroing (T-47-01).
   *
   * @param parentIpnsName - IPNS name of the folder containing the file
   * @param fileId - ID of the file (FilePointer) whose version is deleted
   * @param versionIndex - Index of the version being deleted (caller-resolved)
   * @param params - Pre-resolved key + metadata + version-pruned updates + deletedCid
   * @returns The deleted version's `deletedCid` plus any `prunedCids` produced by a
   *   409-conflict merge round inside `updateFileMetadata` — the caller must unpin both.
   */
  /**
   * @stub phase 65 (write-chain): VersionEntry replaces FileMetadata.versions[];
   * version delete will remove a VersionEntry from NodeContent and publish an
   * updated Node via the write-chain. updateFileMetadata is stubbed in sdk-core.
   */
  async deleteFileVersion(
    parentIpnsName: string,
    fileId: string,
    versionIndex: number,
    params: {
      fileIpnsPrivateKey: Uint8Array;
      currentMetadata: unknown;
      updates: unknown;
      deletedCid?: string;
      maxVersionsPerFile?: number;
      migratedIpnsPrivateKeyEncrypted?: string;
    }
  ): Promise<{ deletedCid?: string; prunedCids: string[] }> {
    void parentIpnsName;
    void fileId;
    void versionIndex;
    void params;
    throw new Error('not implemented — phase 65 (write-chain: deleteFileVersion)');
  }

  /**
   * Conditional folder re-publish for lazy IPNS-key migration.
   *
   * When `migratedIpnsPrivateKeyEncrypted` is provided, snapshot baseChildren,
   * bump the matching FilePointer's `modifiedAt` + `ipnsPrivateKeyEncrypted`,
   * publish via `updateFolderMetadataAndPublish`, and adopt the merged result
   * into the folder state. No-op (folder children + sequence unchanged) when
   * no migration is needed — the file-only publish does not advance the folder
   * sequence. Mutates `folder` in place; callers persist it via folderTree.set.
   */

  /**
   * Download a file using its per-file IPNS metadata.
   *
   * Resolves the file's IPNS record, decrypts the metadata with the
   * folder key, then downloads and decrypts the file content.
   * This is the primary download path for v2 folder metadata.
   *
   * @param fileMetaIpnsName - IPNS name of the file's metadata record
   * @param folderKey - Parent folder's decrypted AES-256 key
   * @param onProgress - Optional download progress callback
   * @returns Decrypted file content
   */
  /**
   * @stub phase 65 (write-chain): resolveFileMetadata returns { metadata: unknown };
   * the file's content-encryption fields now live in NodeContent inside the sealed
   * Node, not in a standalone FileMetadata IPNS record. Phase 65 will unseal
   * NodeContent from the file's Node and call downloadAndDecrypt with those fields.
   */
  async downloadFromIpns(
    fileMetaIpnsName: string,
    folderKey: Uint8Array,
    onProgress?: DownloadProgressCallback
  ): Promise<Uint8Array> {
    void fileMetaIpnsName;
    void folderKey;
    void onProgress;
    throw new Error('not implemented — phase 65 (write-chain: downloadFromIpns)');
  }

  /**
   * Download and decrypt a file from IPFS.
   *
   * Fetches the encrypted file content, unwraps the file key using the
   * user's private key, and decrypts the content.
   *
   * @param cid - IPFS CID of the encrypted file content
   * @param fileKeyEncrypted - Hex-encoded ECIES-wrapped file key
   * @param fileIv - Hex-encoded IV used for encryption
   * @param encryptionMode - 'GCM' (default) or 'CTR'
   * @param onProgress - Optional download progress callback
   * @returns Decrypted file content
   */
  async downloadFile(
    cid: string,
    fileKeyEncrypted: string,
    fileIv: string,
    encryptionMode?: 'GCM' | 'CTR',
    onProgress?: DownloadProgressCallback
  ): Promise<Uint8Array> {
    return this.withOperation('downloadFile', async () => {
      const plaintext = await sdkCore.downloadAndDecrypt({
        cid,
        fileKeyEncrypted,
        fileIv,
        userPrivateKey: this.config.vaultKeypair.privateKey,
        encryptionMode,
        ctx: this.ctx,
        onProgress,
      });

      this.emitter.emit({ type: 'file:downloaded', cid });

      return plaintext;
    });
  }

  // ---- Bin operations ----

  /**
   * Load the recycle bin metadata.
   *
   * Always returns a BinState — if no bin IPNS record exists yet,
   * returns empty state so deleteToBin can create the first record.
   */
  async loadBin(): Promise<BinState> {
    return this.withOperation('loadBin', async () => {
      const result = await binOps.loadBin({
        binCtx: this.getBinContext(),
      });

      // Anti-clobber guard. loadBin returns an in-memory empty fallback
      // (entries=[], sequenceNumber=0) when the bin record can't be resolved —
      // e.g. a transient cold-cache/404 right after a reload. Bin init is
      // fire-and-forget on login (useAuth) AND BinBrowser calls loadBin on
      // mount, so two loads race. If one resolves the real bin (entries present)
      // and the other transiently misses, the miss must NOT wipe the already
      // loaded state.
      const existing = this.binState;
      const isEmptyFallback = result.sequenceNumber === 0 && result.entries.length === 0;
      if (isEmptyFallback) {
        // The empty fallback is "couldn't resolve a record", not an authoritative
        // empty bin. If we already hold loaded state, keep it untouched. Otherwise
        // adopt the empty state so deleteToBin can create the first record, but do
        // NOT broadcast bin:updated — there is nothing to show and emitting an
        // empty event would clobber a concurrently-loaded bin in subscribers.
        if (existing !== null) {
          return existing;
        }
        this.binState = result;
        return result;
      }

      this.binState = result;
      this.emitter.emit({ type: 'bin:updated', entries: result.entries });

      return result;
    });
  }

  /**
   * Soft-delete an item by moving it to the recycle bin.
   *
   * Removes the item from the folder's metadata, adds a BinEntry,
   * and publishes both folder and bin IPNS records.
   *
   * @param folderIpnsName - IPNS name of the folder containing the item
   * @param childId - ID of the child to delete
   * @param parentPath - Breadcrumb path for restore (e.g., "My Vault / Documents")
   */
  async deleteToBin(folderIpnsName: string, childId: string, parentPath: string): Promise<void> {
    return this.withOperation('deleteToBin', async () => {
      // Self-heal: bin init is fire-and-forget on login (useAuth), so binState may
      // still be null when a delete fires (e.g. delete soon after login, or right
      // after a reload). Without this, deleteToBin throws BinNotLoadedError and the
      // web falls back to a HARD delete — the item vanishes and never reaches the
      // bin. Lazily load the bin here so soft-delete always works.
      if (!this.binState) {
        await this.loadBin();
      }
      if (!this.binState) throw new BinNotLoadedError();

      // Self-bootstrap the folder if it isn't loaded (e.g. after a reload), so
      // addToBin can read its keys to republish the parent.
      await this.requireFolder(folderIpnsName);

      const { updatedBinState } = await binOps.addToBin({
        folderIpnsName,
        childId,
        parentPath,
        folderTree: this.folderTree,
        binState: this.binState,
        binCtx: this.getBinContext(),
        revokeSharesForItemsFn: (ipnsNames) => this.revokeSharesForItems(ipnsNames),
      });

      this.binState = updatedBinState;

      // Emit events
      const folderState = this.folderTree.get(folderIpnsName);
      this.emitter.emit({
        type: 'folder:updated',
        folderId: folderIpnsName,
        ipnsName: folderIpnsName,
        children: folderState?.children ?? [],
        sequenceNumber: folderState?.sequenceNumber ?? 0n,
      });
      this.emitter.emit({ type: 'bin:updated', entries: updatedBinState.entries });

      // No IPNS unenrollment here — soft delete preserves items for restore.
      // Unenrollment happens on permanentDelete() or emptyBin().
    });
  }

  /**
   * Restore an item from the recycle bin to its target folder.
   *
   * @param entryId - ID of the bin entry to restore
   * @param targetFolderIpnsName - IPNS name of the folder to restore to
   */
  async restoreFromBin(entryId: string, targetFolderIpnsName: string): Promise<void> {
    return this.withOperation('restoreFromBin', async () => {
      if (!this.binState) throw new BinNotLoadedError();

      // Self-bootstrap the target folder if it isn't loaded. After a reload the
      // user may restore into a folder they never navigated to this session;
      // requireFolder walks from root and unwraps its keys so restoreFromBin can
      // republish the parent (fixes 'Target folder not loaded').
      await this.requireFolder(targetFolderIpnsName, 'Target folder');

      const { updatedBinState } = await binOps.restoreFromBin({
        entryId,
        targetFolderIpnsName,
        folderTree: this.folderTree,
        binState: this.binState,
        binCtx: this.getBinContext(),
      });

      this.binState = updatedBinState;

      // Emit events
      const targetState = this.folderTree.get(targetFolderIpnsName);
      this.emitter.emit({
        type: 'folder:updated',
        folderId: targetFolderIpnsName,
        ipnsName: targetFolderIpnsName,
        children: targetState?.children ?? [],
        sequenceNumber: targetState?.sequenceNumber ?? 0n,
      });
      this.emitter.emit({ type: 'bin:updated', entries: updatedBinState.entries });
    });
  }

  /**
   * Permanently delete a bin entry (unpin CIDs, remove from bin).
   *
   * @param entryId - ID of the bin entry to permanently delete
   */
  async permanentDelete(entryId: string): Promise<void> {
    return this.withOperation('permanentDelete', async () => {
      if (!this.binState) throw new BinNotLoadedError();

      // Capture entry before deletion for IPNS unenrollment
      const entry = this.binState.entries.find((e) => e.id === entryId);

      const { updatedBinState } = await binOps.permanentDeleteFromBin({
        entryId,
        binState: this.binState,
        binCtx: this.getBinContext(),
      });

      this.binState = updatedBinState;
      this.emitter.emit({ type: 'bin:updated', entries: updatedBinState.entries });

      // Fire-and-forget IPNS unenrollment for permanently deleted bin entry
      if (entry) {
        this.fireAndForgetUnenrollEntries([entry]);
      }
    });
  }

  /**
   * Permanently delete all bin entries.
   */
  async emptyBin(): Promise<void> {
    return this.withOperation('emptyBin', async () => {
      if (!this.binState) throw new BinNotLoadedError();

      // Capture entries before emptying so async collection can proceed after the bin is cleared
      const entriesToUnenroll = [...this.binState.entries];

      const { updatedBinState } = await binOps.emptyBin({
        binState: this.binState,
        binCtx: this.getBinContext(),
      });

      this.binState = updatedBinState;
      this.emitter.emit({ type: 'bin:updated', entries: [] });

      // Fire-and-forget IPNS unenrollment: collect async (on-demand subtree fetch) then dispatch.
      this.fireAndForgetUnenrollEntries(entriesToUnenroll);
    });
  }

  /**
   * Purge expired entries from the recycle bin.
   *
   * Cleans up IPFS CIDs for expired entries and removes them from bin metadata.
   *
   * @param retentionDays - Retention period in days. Entries older than this are purged.
   * @returns Number of entries purged
   */
  async purgeExpired(retentionDays: number): Promise<number> {
    return this.withOperation('purgeExpired', async () => {
      if (!Number.isFinite(retentionDays)) {
        throw new TypeError('purgeExpired: retentionDays must be a finite number');
      }
      const normalizedDays = Math.max(0, Math.floor(retentionDays));
      if (!this.binState) throw new BinNotLoadedError();

      const previousEntries = this.binState.entries;
      const { purgedCount, updatedState } = await binOps.purgeExpiredEntries({
        binState: this.binState,
        retentionDays: normalizedDays,
        binCtx: this.getBinContext(),
      });

      if (purgedCount > 0) {
        // Unenroll IPNS names for purged entries (same as permanentDelete/emptyBin)
        const purgedEntries = previousEntries.filter(
          (entry) => !updatedState.entries.some((next) => next.id === entry.id)
        );
        this.binState = updatedState;
        this.emitter.emit({ type: 'bin:updated', entries: updatedState.entries });
        // Fire-and-forget IPNS unenrollment: collect async (on-demand subtree fetch) then dispatch.
        this.fireAndForgetUnenrollEntries(purgedEntries);
      }

      return purgedCount;
    });
  }

  // ---- Share operations ----

  /**
   * Create an ECIES-wrapped key for sharing a folder with a recipient.
   *
   * @param folderIpnsName - IPNS name of the folder to share
   * @param recipientPublicKey - Recipient's secp256k1 public key
   * @returns Hex-encoded wrapped key for the recipient
   */
  async shareFolder(
    folderIpnsName: string,
    recipientPublicKey: Uint8Array
  ): Promise<{ encryptedKey: string }> {
    return this.withOperation('shareFolder', async () => {
      const folder = await this.requireFolder(folderIpnsName);

      return shareOps.createShareKey({
        folderKey: folder.folderKey,
        recipientPublicKey,
        folderIpnsName,
        shareCtx: this.getShareContext(),
      });
    });
  }

  /**
   * Revoke a share (soft-delete).
   *
   * @param shareId - Share ID to revoke
   * @param revokeShareFn - Function to call the API revoke endpoint
   */
  async revokeShare(
    shareId: string,
    revokeShareFn: (shareId: string) => Promise<void>
  ): Promise<void> {
    return this.withOperation('revokeShare', async () => {
      await shareOps.revokeShare({ shareId, revokeShareFn });
    });
  }

  // ---- Shared-folder operations (REQ-3) ----

  /**
   * Register / seed shared-folder state in the SDK's sibling `sharedFolderTree`.
   *
   * Mirrors {@link registerFolder} for the SHARED path. The consumer resolves
   * the share (folder key, IPNS private key, owner + recipient pubkeys,
   * children, sequence number, addShareKeys callback) and seeds it here keyed by
   * `shareId`. The five shared write methods below then own publish + sequence
   * bookkeeping + `sharedFolder:updated` emission, delegating the actual write to
   * the stateless `share/shared-write.ts` functions.
   *
   * `SharedFolderTree.set()` clones the key buffers, so the caller's `folderKey`
   * / `ipnsPrivateKey` buffers are never zeroed by `destroy()` / `delete()`.
   *
   * @param shareId - Share ID — the key under which this state lives
   * @param state - Initial shared-folder state
   */
  loadSharedFolder(shareId: string, state: SharedFolderState): void {
    this.sharedFolderTree.set(shareId, { ...state, shareId });
  }

  /**
   * Check if a shared folder is registered in the SDK's sharedFolderTree.
   */
  hasSharedFolder(shareId: string): boolean {
    return this.sharedFolderTree.has(shareId);
  }

  /**
   * Get a snapshot of a shared folder's current state (or undefined).
   * Returns the internal reference — consumers must not mutate it.
   */
  getSharedFolderState(shareId: string): SharedFolderState | undefined {
    return this.sharedFolderTree.get(shareId);
  }

  /** Remove a shared folder from the SDK, zeroing its key material. */
  unloadSharedFolder(shareId: string): void {
    this.sharedFolderTree.delete(shareId);
  }

  /**
   * Read shared-folder state for `shareId`, throwing a uniform error if absent.
   * All shared write methods route through this to enforce the load contract.
   */
  private requireSharedFolder(shareId: string): SharedFolderState {
    const state = this.sharedFolderTree.get(shareId);
    if (!state) throw new Error('Shared folder not loaded');
    return state;
  }

  /**
   * Build a SharedWriteContext from the current shared-folder state.
   * The state's per-share owner/recipient pubkeys, IPNS key, and addShareKeys
   * callback are carried into the context — no cross-share bleed (T-48-07).
   *
   * addToIpfsFn: thin wrapper over sdkCore.addToIpfs — uploads raw bytes and
   * returns the resulting CID. Used by write-body ops to upload encrypted content.
   *
   * publishNodeFn: uploads the sealed PublishedNode JSON to IPFS then calls
   * createAndPublishIpnsRecord with the supplied sequenceNumber (callers in
   * shared-write.ts supply the target new sequence directly). Returns the
   * new sequence number echoed from the API response.
   */
  private buildSharedWriteContextFromState(
    state: SharedFolderState
  ): ReturnType<typeof shareOps.buildSharedWriteContext> {
    return shareOps.buildSharedWriteContext({
      ctx: this.ctx,
      readKey: state.folderKey,
      writeKey: state.writeKey,
      publishedNode: state.publishedNode,
      ipnsName: state.ipnsName,
      sequenceNumber: state.sequenceNumber,
      children: state.children,
      ownerPublicKey: state.ownerPublicKey,
      recipientPublicKey: state.recipientPublicKey,
      shareId: state.shareId,
      addToIpfsFn: async (data) => {
        const result = await sdkCore.addToIpfs(this.ctx, data);
        return { cid: result.cid };
      },
      publishNodeFn: async ({ published, ipnsName, ipnsPrivateKey, sequenceNumber }) => {
        const bytes = new TextEncoder().encode(JSON.stringify(published));
        const ipfsResult = await sdkCore.addToIpfs(this.ctx, bytes);
        const pubResult = await sdkCore.createAndPublishIpnsRecord({
          ipnsPrivateKey,
          ipnsName,
          metadataCid: ipfsResult.cid,
          sequenceNumber,
          ctx: this.ctx,
        });
        return { tombstoned: false, newSequenceNumber: pubResult.sequenceNumber };
      },
      addShareKeysFn: state.addShareKeysFn,
    });
  }

  /**
   * Adopt a shared-write result into `sharedFolderTree` and emit
   * `sharedFolder:updated`. Centralizes the write-back + emission so all five
   * methods stay consistent.
   */
  private adoptSharedFolderResult(
    shareId: string,
    result: { publishedChildren: SealedChildRef[]; newSequenceNumber: bigint }
  ): void {
    // Re-read live state: the share may have been unloaded (e.g. unmount →
    // unloadSharedFolder) while the async write/refresh was in-flight. Never
    // resurrect an explicitly-unloaded share from a pre-await snapshot.
    const live = this.sharedFolderTree.get(shareId);
    if (!live) return;
    const next: SharedFolderState = {
      ...live,
      children: result.publishedChildren,
      sequenceNumber: result.newSequenceNumber,
    };
    this.sharedFolderTree.set(shareId, next);
    this.emitter.emit({
      type: 'sharedFolder:updated',
      shareId,
      ipnsName: live.ipnsName,
      children: result.publishedChildren,
      sequenceNumber: result.newSequenceNumber,
    });
  }

  /**
   * Upload a file to a write-shared folder (REQ-3).
   *
   * Reads state from `sharedFolderTree`, delegates to the stateless
   * `uploadToSharedFolder` (which routes through `publishWithCas` — the one CAS
   * engine; no second retry loop here), adopts the published children + sequence,
   * and emits `sharedFolder:updated`.
   */
  async uploadToSharedFolder(
    shareId: string,
    args: { data: Uint8Array; fileName: string; mimeType?: string }
  ): Promise<void> {
    return this.withOperation('uploadToSharedFolder', async () => {
      const state = this.requireSharedFolder(shareId);
      const result = await shareOps.uploadToSharedFolder(
        this.buildSharedWriteContextFromState(state),
        args
      );
      this.adoptSharedFolderResult(shareId, result);
    });
  }

  /**
   * Create a subfolder in a write-shared folder (REQ-3).
   */
  async createSharedSubfolder(shareId: string, args: { name: string }): Promise<void> {
    return this.withOperation('createSharedSubfolder', async () => {
      const state = this.requireSharedFolder(shareId);
      const result = await shareOps.createSharedSubfolder(
        this.buildSharedWriteContextFromState(state),
        args
      );
      this.adoptSharedFolderResult(shareId, result);
    });
  }

  /**
   * Rename an item in a write-shared folder (REQ-3).
   */
  async renameInSharedFolder(
    shareId: string,
    args: { itemId: string; newName: string }
  ): Promise<void> {
    return this.withOperation('renameInSharedFolder', async () => {
      const state = this.requireSharedFolder(shareId);
      const result = await shareOps.renameInSharedFolder(
        this.buildSharedWriteContextFromState(state),
        args
      );
      this.adoptSharedFolderResult(shareId, result);
    });
  }

  /**
   * Delete an item from a write-shared folder (REQ-3).
   *
   * @param args.itemId - IPNS name of the item (read-body key).
   * @param args.childNodeId - UUID of the child node (write-body key; minted at
   *   creation time by uploadToSharedFolder / createSharedSubfolder).
   */
  async deleteFromSharedFolder(
    shareId: string,
    args: { itemId: string; childNodeId: string }
  ): Promise<void> {
    return this.withOperation('deleteFromSharedFolder', async () => {
      // Public SDK boundary: a missing childNodeId would remove the read-body item
      // while leaving the write-body WriteChildRef stale, which later breaks
      // rotateWriteFromNode — fail closed before delegating.
      if (typeof args.childNodeId !== 'string' || args.childNodeId.trim().length === 0) {
        throw new TypeError('deleteFromSharedFolder: childNodeId is required');
      }
      const state = this.requireSharedFolder(shareId);
      const result = await shareOps.deleteFromSharedFolder(
        this.buildSharedWriteContextFromState(state),
        args
      );
      this.adoptSharedFolderResult(shareId, result);
    });
  }

  /**
   * Update a file's content in a write-shared folder (REQ-3).
   *
   * This is the FILE path: the stateless `updateSharedFile` publishes the file's
   * own IPNS metadata via CAS and does NOT advance the parent folder's children
   * or sequence (the FilePointer is unchanged). It returns void, so no
   * write-back occurs — but we still emit `sharedFolder:updated` with the
   * unchanged children/sequence so consumers re-resolve the file (mirrors the
   * owned `restoreFileVersion` file-only emission).
   *
   * The caller pre-resolves `filePointer` and supplies `getFileIpnsKeyFn`
   * (share-key lookup with FilePointer fallback). `ctx`, `folderKey`,
   * owner/recipient pubkeys, `shareId`, and `addShareKeysFn` come from state.
   */
  /**
   * @stub phase 65 (write-chain): FilePointer replaced by SealedChildRef;
   * updateSharedFile in share/shared-write.ts is stubbed for phase 65.
   */
  async updateSharedFile(
    shareId: string,
    args: {
      filePointer: SealedChildRef;
      newContent: Uint8Array;
      getFileIpnsKeyFn: (itemId: string) => Promise<Uint8Array | null>;
    }
  ): Promise<void> {
    void shareId;
    void args;
    throw new Error('not implemented — phase 65 (write-chain: updateSharedFile)');
  }

  /**
   * Re-resolve a shared folder's IPNS record and adopt remote changes (REQ-3).
   *
   * The shared analog of {@link loadFolder}/`ensureFolderLoaded` for the owned
   * path: the SDK — not the consumer — owns shared-folder REFRESH. The web 30s
   * poller calls this instead of resolving IPNS / fetching IPFS / decrypting
   * inline, so `sharedFolder:updated` is the sole ref writer on BOTH the write
   * and poll paths.
   *
   * Re-resolves via `sdkCore.loadFolderMetadata` using the stored `ipnsName` +
   * `folderKey`, then applies the #489 sequence-as-clock guard: when the
   * resolved sequence is stale/equal (`state.sequenceNumber >=
   * result.sequenceNumber`) it re-emits the EXISTING (fresher) snapshot instead
   * of clobbering it — a background poll never regresses just-written in-memory
   * state. A newer sequence is adopted into `sharedFolderTree` via
   * `adoptSharedFolderResult` (identical emission shape to the write path). A
   * null result (unresolvable IPNS) is a no-op.
   *
   * @throws if the share is not loaded (same contract as the write methods).
   */
  async refreshSharedFolder(shareId: string): Promise<void> {
    return this.withOperation('refreshSharedFolder', async () => {
      const state = this.requireSharedFolder(shareId);

      const result = await sdkCore.loadFolderMetadata({
        ipnsName: state.ipnsName,
        folderKey: state.folderKey,
        ctx: this.ctx,
      });

      if (!result) return;

      // IPNS reads lag a just-written sequence (#489 sequence-as-clock invariant).
      // Never overwrite a fresher in-memory entry with a stale IPNS snapshot —
      // re-emit the existing snapshot so consumers stay consistent.
      if (state.sequenceNumber >= result.sequenceNumber) {
        // Re-read live state after the await: no-op if unloaded mid-flight, and
        // re-emit the freshest in-memory snapshot (a concurrent write may have
        // advanced it past the pre-await `state`).
        const live = this.sharedFolderTree.get(shareId);
        if (!live) return;
        this.emitter.emit({
          type: 'sharedFolder:updated',
          shareId,
          ipnsName: live.ipnsName,
          children: live.children,
          sequenceNumber: live.sequenceNumber,
        });
        return;
      }

      this.adoptSharedFolderResult(shareId, {
        publishedChildren: result.metadata.children ?? [],
        newSequenceNumber: result.sequenceNumber,
      });
    });
  }

  /**
   * Move an item between two subfolders within a single shared folder (REQ-2).
   *
   * Resolves the destination folder's keys from `share_keys` (recipient-wrapped),
   * loads fresh dest children via `loadFolderMetadata` (A1 — never a cached ref),
   * delegates to the stateless `moveInSharedFolder` op (publish DEST → re-key →
   * publish SOURCE), adopts the SOURCE result into `sharedFolderTree`, and
   * emits `sharedFolder:updated` for the active depth (source).
   *
   * Write-capability guard (T-49-01): requires a `share_keys keyType:'folder-ipns'`
   * entry for `destFolderId` — absence throws before any publish.
   *
   * Key zeroing (T-49-04): `destFolderKey`, `destIpnsPrivateKey`, and
   * `fileIpnsPrivateKey` are zeroed in `finally` (caller owns `vaultPrivateKey`).
   */
  /**
   * @stub phase 63 (navigation): SealedChildRef has no type discriminant and no
   * folderKeyEncrypted/ipnsPrivateKeyEncrypted fields; the phase-63 DFS will
   * unseal the child readKey from SealedChildRef.readKeySealed using the parent
   * Node's readKey chain. moveInSharedFolder in share/shared-write.ts also stubbed.
   */
  async moveInSharedFolder(
    shareId: string,
    args: {
      itemId: string;
      destFolderId: string;
      destIpnsName: string;
      vaultPrivateKey: Uint8Array;
      getShareKeysFn: (
        shareId: string
      ) => Promise<Array<{ keyType: string; itemId: string; encryptedKey: string }>>;
    }
  ): Promise<void> {
    void shareId;
    void args;
    throw new Error('not implemented — phase 63 (navigation: moveInSharedFolder)');
  }

  /**
   * Enumerate all reachable subfolders within a shared folder tree (DFS).
   *
   * Uses share_keys entries (ECIES-wrapped per recipient in the current schema) to
   * derive each subfolder's readKey, loading children via the read-chain. Writable
   * status is determined by the presence of a `keyType: 'folder-ipns'` entry for
   * the node in the share_keys table.
   *
   * D-09 zeroization: caller owns `vaultPrivateKey` — this method does NOT zero it.
   * Per-node childFolderKey buffers (locally minted via unwrapKey) are zeroed in
   * the finally block after each subtree load.
   *
   * @param shareId - Share ID seeded via loadSharedFolder
   * @param args.getShareKeysFn - Returns share_keys entries for this share
   * @param args.vaultPrivateKey - Recipient's vault private key (ECIES unwrap)
   * @returns Flat list of reachable subfolders with writable flag and parentId
   */
  async enumerateSharedSubtree(
    shareId: string,
    args: {
      getShareKeysFn: (
        shareId: string
      ) => Promise<Array<{ keyType: string; itemId: string; encryptedKey: string }>>;
      vaultPrivateKey: Uint8Array;
    }
  ): Promise<
    Array<{
      id: string;
      name: string;
      ipnsName: string;
      writable: boolean;
      parentId: string | null;
    }>
  > {
    return this.withOperation('enumerateSharedSubtree', async () => {
      const state = this.sharedFolderTree.get(shareId);
      if (!state) throw new Error('Shared folder not loaded');

      const shareKeys = await args.getShareKeysFn(shareId);

      // Build maps: ipnsName → encryptedKey (folder readKey) and writable set
      const folderKeyMap = new Map<string, string>();
      const writableSet = new Set<string>();
      for (const key of shareKeys) {
        if (key.keyType === 'folder') {
          folderKeyMap.set(key.itemId, key.encryptedKey);
        } else if (key.keyType === 'folder-ipns') {
          writableSet.add(key.itemId);
        }
      }

      const result: Array<{
        id: string;
        name: string;
        ipnsName: string;
        writable: boolean;
        parentId: string | null;
      }> = [];

      // Visited guard prevents infinite loops on cyclic ipnsName references
      const visited = new Set<string>();

      // Iterative DFS stack — each entry is (children array, parent ipnsName)
      const stack: Array<{ children: SealedChildRef[]; parentId: string | null }> = [
        { children: state.children, parentId: null },
      ];

      while (stack.length > 0) {
        const frame = stack.pop()!;
        for (const child of frame.children) {
          if (visited.has(child.ipnsName)) continue;

          // Only enumerate subfolders that have a share key entry
          const encryptedKey = folderKeyMap.get(child.ipnsName);
          if (!encryptedKey) continue;

          visited.add(child.ipnsName);
          const writable = writableSet.has(child.ipnsName);

          result.push({
            id: child.ipnsName,
            name: child.name,
            ipnsName: child.ipnsName,
            writable,
            parentId: frame.parentId,
          });

          // Decrypt child folder key to load its children
          // D-09: childFolderKey is locally minted here — zero it in finally
          let childFolderKey: Uint8Array | null = null;
          try {
            const encKeyBytes = hexToBytes(encryptedKey);
            childFolderKey = await unwrapKey(encKeyBytes, args.vaultPrivateKey);

            const subMeta = await sdkCore.loadFolderMetadata({
              ipnsName: child.ipnsName,
              folderKey: childFolderKey,
              ctx: this.ctx,
            });

            const subChildren = subMeta?.metadata.children;
            if (subChildren && subChildren.length > 0) {
              stack.push({ children: subChildren, parentId: child.ipnsName });
            }
          } finally {
            if (childFolderKey) clearBytes(childFolderKey);
          }
        }
      }

      return result;
    });
  }

  // ---- BYO-IPFS pinning ----

  /**
   * Pin encrypted data according to the configured pinning mode.
   * Returns { cid, size } regardless of mode.
   *
   * Mode behavior:
   * - cipherbox: standard addToIpfs (default, unchanged)
   * - external+Kubo: KuboProvider.pin() directly, NO CipherBox relay.
   *   If Kubo unreachable, throws (no silent fallback).
   * - external+PSA: CipherBox relay for CID acquisition (PSA is CID-reference-only),
   *   then PSA pinByCid, then unpin from CipherBox.
   * - dual: CipherBox primary (must succeed), external secondary (best-effort).
   */
  private async pinWithMode(
    encryptedData: Uint8Array,
    ctx: SdkContext,
    onProgress?: ProgressCallback
  ): Promise<{ cid: string; size: number; secondaryWarning?: string }> {
    const mode = this.config.pinningConfig?.mode ?? 'cipherbox';

    if (mode === 'cipherbox' || !this.externalProvider) {
      // Default: upload via CipherBox API relay
      const result = await sdkCore.addToIpfs(ctx, encryptedData, onProgress);
      return { cid: result.cid, size: result.size };
    }

    if (mode === 'external') {
      const ext = this.config.pinningConfig!.externalProvider!;

      if (ext.protocol === 'kubo' || ext.protocol === 'pinata') {
        // Direct upload to user's node -- NO CipherBox involvement at all.
        // If node is unreachable, this throws. No silent fallback.
        const result = await this.externalProvider.pin(encryptedData);
        // Register CID with API for advisory tracking (best-effort — failure must not block upload)
        try {
          await sdkCore.registerCid(ctx, result.cid, result.size);
        } catch {
          // Advisory tracking failure is non-fatal — pin succeeded on external node
        }
        return { cid: result.cid, size: result.size };
      }

      // PSA: upload to CipherBox relay first (PSA can't accept raw data),
      // then tell PSA to pin the CID, then unpin from CipherBox.
      const relayResult = await sdkCore.addToIpfs(ctx, encryptedData, onProgress);
      try {
        await (this.externalProvider as sdkCore.PsaProvider).pinByCid(relayResult.cid);
      } catch (err) {
        // PSA pin failed, but data is still on CipherBox node
        throw new Error(
          `External PSA pin failed: ${err instanceof Error ? err.message : String(err)}. Data remains on CipherBox node.`
        );
      }
      // PSA accepted the pin request -- unpin from CipherBox (async, best-effort)
      sdkCore
        .unpinFromIpfs(ctx, relayResult.cid)
        .catch((err: unknown) =>
          console.warn('[SDK] Unpin from CipherBox after PSA pin failed:', err)
        );
      // Register CID for advisory tracking (best-effort)
      try {
        await sdkCore.registerCid(ctx, relayResult.cid, relayResult.size);
      } catch {
        // Advisory tracking failure is non-fatal
      }
      return { cid: relayResult.cid, size: relayResult.size };
    }

    // Dual mode: primary to CipherBox, secondary to external (best-effort)
    const primaryResult = await sdkCore.addToIpfs(ctx, encryptedData, onProgress);
    let secondaryWarning: string | undefined;
    try {
      const ext = this.config.pinningConfig!.externalProvider!;
      if (ext.protocol === 'kubo' || ext.protocol === 'pinata') {
        await this.externalProvider.pin(encryptedData);
      } else {
        await (this.externalProvider as sdkCore.PsaProvider).pinByCid(primaryResult.cid);
      }
    } catch {
      secondaryWarning = `mirror to ${this.config.pinningConfig?.externalProvider?.providerName ?? 'external node'} failed (best-effort, no automatic retry)`;
    }
    return { cid: primaryResult.cid, size: primaryResult.size, secondaryWarning };
  }

  // ---- Private helpers ----

  /** Build bin operation context from client config */
  private getBinContext(): binOps.BinOperationContext {
    return {
      ctx: this.ctx,
      userPrivateKey: this.config.vaultKeypair.privateKey,
      userPublicKey: this.config.vaultKeypair.publicKey,
      rootFolderKey: this.config.rootFolderKey,
      teeKeys: this.config.teeKeys,
    };
  }

  /** Build share operation context from client config */
  private getShareContext(): shareOps.ShareOperationContext {
    return {
      ctx: this.ctx,
      userPrivateKey: this.config.vaultKeypair.privateKey,
      userPublicKey: this.config.vaultKeypair.publicKey,
    };
  }

  // ---- Operation wrapper ----

  /**
   * Wrap an async operation with event emission and error handling.
   *
   * Emits 'operation:start' before, 'operation:end' on success (with duration),
   * and 'error' on failure. Also calls the config callbacks if provided.
   */
  private async withOperation<T>(name: string, fn: () => Promise<T>): Promise<T> {
    const start = Date.now();
    this.notifySafely(() => this.config.onOperationStart?.(name));
    this.emitter.emit({ type: 'operation:start', operation: name });

    try {
      const result = await fn();
      const durationMs = Date.now() - start;
      this.notifySafely(() => this.config.onOperationEnd?.(name));
      this.emitter.emit({ type: 'operation:end', operation: name, durationMs });
      return result;
    } catch (error) {
      this.notifySafely(() => this.config.onError?.(error as Error));
      this.emitter.emit({ type: 'error', operation: name, error: error as Error });
      throw error;
    }
  }

  private notifySafely(fn: () => void): void {
    try {
      fn();
    } catch (err) {
      console.warn('[SDK] Lifecycle callback threw:', err);
    }
  }
}
