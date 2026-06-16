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
import { createAxiosInstance, ipnsControllerUnenrollBatch } from '@cipherbox/api-client';
import { clearBytes, unwrapKey, hexToBytes } from '@cipherbox/crypto';
import pLimit from 'p-limit';
import type {
  FolderChild,
  FolderEntry,
  FilePointer,
  BinEntry,
  FileMetadata,
} from '@cipherbox/core';
import type { CipherBoxClientConfig, FolderState, SharedFolderState } from './types';
import { SdkEventEmitter, type SdkEvent, type SdkEventHandler } from './events';
import { FolderTree } from './state/folder-tree';
import { SharedFolderTree } from './state/shared-folder-tree';
import { KeyCache } from './state/key-cache';
import * as binOps from './bin';
import type { BinState } from './bin';
import * as shareOps from './share';
import type { SentShareInfo } from './share';

/** Maximum concurrent encrypt+pin operations for batch uploads. */
const UPLOAD_CONCURRENCY = 3;

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

  // ---- Share re-wrapping (internal) ----

  /**
   * Re-wrap keys for share recipients after adding items to a folder.
   *
   * Queries the share callbacks for active shares covering the folder,
   * then wraps each new item's plaintext key for each recipient.
   * Failures are logged but do not propagate (re-wrapping is best-effort).
   */
  private async reWrapNewItems(
    folderIpnsName: string,
    items: Array<{ keyType: 'file' | 'folder'; itemId: string; plaintextKey: Uint8Array }>
  ): Promise<void> {
    const callbacks = this.config.shareCallbacks;
    if (!callbacks) return;

    const coveringShares = await callbacks.getCoveringShares(folderIpnsName);
    if (coveringShares.length === 0) return;

    const { failedRecipients } = await shareOps.reWrapForRecipients({
      coveringShares,
      newItems: items,
      addShareKeysFn: callbacks.addShareKeys,
    });

    if (failedRecipients.length > 0) {
      console.warn(
        `[SDK] Re-wrapping failed for ${failedRecipients.length} recipient(s):`,
        failedRecipients.map((k) => k.slice(0, 10) + '...')
      );
      this.emitter.emit({
        type: 'share:reWrapFailed',
        folderIpnsName,
        failedRecipients,
      } as SdkEvent);
    }
  }

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

  /** Extract IPNS names from a removed FolderChild (file or folder subtree). */
  private collectRemovedItemIpnsNames(item: FolderChild): string[] {
    if (item.type === 'file') {
      return [(item as FilePointer).fileMetaIpnsName];
    } else if (item.type === 'folder') {
      return this.collectSubtreeIpnsNames((item as FolderEntry).ipnsName);
    }
    return [];
  }

  /** Extract IPNS names from a BinEntry (file pointer and/or folder subtree). */
  private collectBinEntryIpnsNames(entry: BinEntry): string[] {
    const names: string[] = [];
    if (entry.filePointer?.fileMetaIpnsName) {
      names.push(entry.filePointer.fileMetaIpnsName);
    }
    if (entry.folderEntry?.ipnsName) {
      names.push(...this.collectSubtreeIpnsNames(entry.folderEntry.ipnsName));
    }
    return names;
  }

  /**
   * Recursively collect all IPNS names from a folder subtree.
   * Walks the in-memory folderTree to find file IPNS names and subfolder IPNS names.
   * Only collects from loaded folders -- unloaded subtrees are skipped.
   */
  private collectSubtreeIpnsNames(folderIpnsName: string, acc: string[] = []): string[] {
    acc.push(folderIpnsName);
    const folder = this.folderTree.get(folderIpnsName);
    if (!folder) return acc;

    for (const child of folder.children) {
      if (child.type === 'file') {
        acc.push((child as FilePointer).fileMetaIpnsName);
      } else if (child.type === 'folder') {
        this.collectSubtreeIpnsNames((child as FolderEntry).ipnsName, acc);
      }
    }
    return acc;
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
   */
  registerFolder(
    ipnsName: string,
    folderKey: Uint8Array,
    ipnsKeypair: { publicKey: Uint8Array; privateKey: Uint8Array },
    children: FolderChild[],
    sequenceNumber: bigint
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
        children: result.metadata.children,
        metadata: result.metadata,
        lastLoadedAt: Date.now(),
      };

      this.folderTree.set(ipnsName, state);

      this.emitter.emit({
        type: 'folder:loaded',
        folderId: ipnsName,
        ipnsName,
        children: result.metadata.children,
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
  async ensureFolderLoaded(targetIpnsName: string): Promise<FolderState | null> {
    const existing = this.folderTree.get(targetIpnsName);
    if (existing) return existing;

    // Cannot self-bootstrap without the root IPNS signing key.
    if (!this.internalRootIpnsKeypair) return null;

    // 1. Ensure root is loaded. Root is special: it has no parent to unwrap its
    //    keys from, so they come from config (rootFolderKey + rootIpnsKeypair).
    const rootIpnsName = this.config.rootIpnsName;
    const root =
      this.folderTree.get(rootIpnsName) ??
      (await this.loadFolder(
        rootIpnsName,
        this.internalRootFolderKey,
        this.internalRootIpnsKeypair
      ));
    if (!root) return null;
    if (rootIpnsName === targetIpnsName) return root;

    // 2. DFS from root, unwrapping child keys and loading metadata until the
    //    target is found. `visited` guards against repeats and pathological
    //    cycles in folder metadata.
    const visited = new Set<string>([rootIpnsName]);
    const stack: FolderState[] = [root];
    while (stack.length > 0) {
      const current = stack.pop() as FolderState;
      for (const child of current.children) {
        // type === 'folder' narrows child to FolderEntry (discriminated union).
        if (child.type !== 'folder') continue;
        if (visited.has(child.ipnsName)) continue;
        visited.add(child.ipnsName);

        let childState = this.folderTree.get(child.ipnsName) ?? null;
        if (!childState) {
          try {
            // Unwrap this subfolder's keys with the vault keypair (ECIES), then
            // load its metadata. loadFolder adopts independent clones into the
            // folderTree (zeroed on destroy()); the transient unwrapped buffers
            // are left to GC, matching the existing loadFolder/registerFolder
            // paths which likewise don't eagerly zero their unwrapped inputs.
            const folderKey = await unwrapKey(
              hexToBytes(child.folderKeyEncrypted),
              this.internalVaultKeypair.privateKey
            );
            const ipnsPrivateKey = await unwrapKey(
              hexToBytes(child.ipnsPrivateKeyEncrypted),
              this.internalVaultKeypair.privateKey
            );
            childState = await this.loadFolder(child.ipnsName, folderKey, {
              // Public key is derived from the private key at signing time.
              publicKey: new Uint8Array(0),
              privateKey: ipnsPrivateKey,
            });
          } catch {
            // A single corrupt/undecryptable sibling entry must not abort the
            // whole bootstrap — skip it so unrelated targets stay reachable.
            // (Generic catch: unwrapKey/hexToBytes throw key-free errors.)
            continue;
          }
        }
        // Could not resolve this subfolder (no IPNS record) — skip it.
        if (!childState) continue;
        if (child.ipnsName === targetIpnsName) return childState;
        stack.push(childState);
      }
    }

    // Target not found anywhere under root.
    return null;
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
  async createFolder(
    parentIpnsName: string,
    name: string
  ): Promise<{ id: string; ipnsName: string; folderKey: Uint8Array; ipnsPrivateKey: Uint8Array }> {
    return this.withOperation('createFolder', async () => {
      const parent = await this.requireFolder(parentIpnsName, 'Parent folder');

      // 1. Check for duplicate name before allocating keys
      if (parent.children.some((child) => child.name === name)) {
        throw new Error('An item with this name already exists');
      }

      // 2. Create subfolder (generates keys, wraps with user public key)
      const { folder, ipnsPrivateKey, folderKey, encryptedIpnsPrivateKey, keyEpoch } =
        await sdkCore.createSubfolder({
          name,
          userPublicKey: this.config.vaultKeypair.publicKey,
          teeKeys: this.config.teeKeys,
        });

      try {
        // 3. Add folder entry to parent's children
        const baseChildren = [...parent.children];
        const updatedChildren: FolderChild[] = [...parent.children, folder];

        // 4. Update parent metadata and publish
        const { newSequenceNumber, publishedChildren } =
          await sdkCore.updateFolderMetadataAndPublish({
            children: updatedChildren,
            baseChildren,
            folderKey: parent.folderKey,
            ipnsPrivateKey: parent.ipnsKeypair.privateKey,
            ipnsName: parentIpnsName,
            sequenceNumber: parent.sequenceNumber,
            ctx: this.ctx,
            encryptedIpnsPrivateKey: encryptedIpnsPrivateKey,
            keyEpoch,
          });

        // 5. Update parent state — adopt merged published set (CR-01)
        parent.children = publishedChildren;
        parent.sequenceNumber = newSequenceNumber;
        parent.lastLoadedAt = Date.now();
        this.folderTree.set(parentIpnsName, parent);

        // 6. Publish empty metadata for the new subfolder
        await sdkCore.updateFolderMetadataAndPublish({
          children: [],
          baseChildren: [],
          folderKey,
          ipnsPrivateKey,
          ipnsName: folder.ipnsName,
          sequenceNumber: 0n,
          ctx: this.ctx,
          encryptedIpnsPrivateKey,
          keyEpoch,
        });

        // 7. Emit parent folder updated event
        this.emitter.emit({
          type: 'folder:updated',
          folderId: parentIpnsName,
          ipnsName: parentIpnsName,
          children: publishedChildren,
          sequenceNumber: newSequenceNumber,
        });

        // 8. Re-wrap subfolder key for share recipients (non-blocking)
        if (this.config.shareCallbacks) {
          // Copy folderKey for the detached task — caller may wipe the returned buffer
          const folderKeyCopy = new Uint8Array(folderKey);
          this.reWrapNewItems(parentIpnsName, [
            { keyType: 'folder', itemId: folder.id, plaintextKey: folderKeyCopy },
          ])
            .catch((err) => {
              console.warn('[SDK] Post-createFolder re-wrapping failed:', err);
            })
            .finally(() => {
              clearBytes(folderKeyCopy);
            });
        }

        return { id: folder.id, ipnsName: folder.ipnsName, folderKey, ipnsPrivateKey };
      } catch (err) {
        // Clear plaintext keys on failure — they won't reach the caller
        clearBytes(folderKey);
        clearBytes(ipnsPrivateKey);
        throw err;
      }
    });
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
   * @param sourceIpnsName - IPNS name of the source folder
   * @param destIpnsName - IPNS name of the destination folder
   * @param childId - ID of the child to move
   */
  async moveItem(sourceIpnsName: string, destIpnsName: string, childId: string): Promise<void> {
    return this.withOperation('moveItem', async () => {
      const source = await this.requireFolder(sourceIpnsName, 'Source folder');
      const dest = await this.requireFolder(destIpnsName, 'Destination folder');

      // 1. Compute updated children for both folders (pure operation)
      const baseDestChildren = [...dest.children];
      const baseSourceChildren = [...source.children];
      const { updatedSourceChildren, updatedDestChildren } = sdkCore.moveItem({
        sourceChildren: source.children,
        destChildren: dest.children,
        childId,
      });

      // 2. Publish destination first (add-before-remove for crash safety)
      const destResult = await sdkCore.updateFolderMetadataAndPublish({
        children: updatedDestChildren,
        baseChildren: baseDestChildren,
        folderKey: dest.folderKey,
        ipnsPrivateKey: dest.ipnsKeypair.privateKey,
        ipnsName: destIpnsName,
        sequenceNumber: dest.sequenceNumber,
        ctx: this.ctx,
      });

      // 3. Publish source (remove)
      const sourceResult = await sdkCore.updateFolderMetadataAndPublish({
        children: updatedSourceChildren,
        baseChildren: baseSourceChildren,
        folderKey: source.folderKey,
        ipnsPrivateKey: source.ipnsKeypair.privateKey,
        ipnsName: sourceIpnsName,
        sequenceNumber: source.sequenceNumber,
        ctx: this.ctx,
      });

      // 4. Update internal state — adopt merged published sets (CR-01)
      source.children = sourceResult.publishedChildren;
      source.sequenceNumber = sourceResult.newSequenceNumber;
      dest.children = destResult.publishedChildren;
      dest.sequenceNumber = destResult.newSequenceNumber;
      this.folderTree.set(sourceIpnsName, source);
      this.folderTree.set(destIpnsName, dest);

      // 5. Emit events for both folders
      this.emitter.emit({
        type: 'folder:updated',
        folderId: sourceIpnsName,
        ipnsName: sourceIpnsName,
        children: sourceResult.publishedChildren,
        sequenceNumber: sourceResult.newSequenceNumber,
      });
      this.emitter.emit({
        type: 'folder:updated',
        folderId: destIpnsName,
        ipnsName: destIpnsName,
        children: destResult.publishedChildren,
        sequenceNumber: destResult.newSequenceNumber,
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
  async deleteItem(folderIpnsName: string, childId: string): Promise<{ removedItem: FolderChild }> {
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

      // 5. Fire-and-forget IPNS unenrollment
      this.fireAndForgetUnenroll(this.collectRemovedItemIpnsNames(removedItem));

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
        // 2. Add FilePointer to folder's children
        const baseChildren = [...folder.children];
        const { updatedChildren } = sdkCore.addFilePointerToFolder({
          children: folder.children,
          fileId,
          fileName,
          fileMetaIpnsName: uploadResult.fileMetaIpnsName,
          ipnsPrivateKeyEncrypted: uploadResult.ipnsPrivateKeyEncrypted,
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

        // 6. Re-wrap file key for share recipients (best-effort)
        try {
          if (this.config.shareCallbacks) {
            await this.reWrapNewItems(folderIpnsName, [
              { keyType: 'file', itemId: fileId, plaintextKey: uploadResult.fileKey },
            ]);
          }
        } catch (err) {
          console.warn('[SDK] Post-upload re-wrapping failed:', err);
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
            const { updatedChildren } = sdkCore.addFilePointerToFolder({
              children: mergedChildren,
              fileId: success.fileId,
              fileName: success.fileName,
              fileMetaIpnsName: success.uploadResult.fileMetaIpnsName,
              ipnsPrivateKeyEncrypted: success.uploadResult.ipnsPrivateKeyEncrypted,
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

        // Re-wrap file keys for share recipients (best-effort)
        try {
          if (this.config.shareCallbacks) {
            await this.reWrapNewItems(
              folderIpnsName,
              registeredSuccesses.map((s) => ({
                keyType: 'file' as const,
                itemId: s.fileId,
                plaintextKey: s.uploadResult.fileKey,
              }))
            );
          }
        } catch (err) {
          console.warn('[SDK] Post-batch-upload re-wrapping failed:', err);
        }

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
  async replaceFile(
    parentIpnsName: string,
    fileId: string,
    fileData: {
      fileIpnsPrivateKey: Uint8Array;
      currentMetadata: FileMetadata;
      updates: Partial<
        Pick<FileMetadata, 'cid' | 'fileKeyEncrypted' | 'fileIv' | 'size' | 'encryptionMode'>
      >;
      createVersion: boolean;
      maxVersionsPerFile?: number;
      /** Hex-encoded re-wrapped IPNS key to persist on the FilePointer (lazy migration). */
      migratedIpnsPrivateKeyEncrypted?: string;
    }
  ): Promise<{ prunedCids: string[] }> {
    return this.withOperation('replaceFile', async () => {
      const folder = await this.requireFolder(parentIpnsName);

      // 1. Find the FilePointer's metadata IPNS name from authoritative state.
      const filePointer = folder.children.find(
        (c): c is FilePointer => c.type === 'file' && c.id === fileId
      );
      if (!filePointer) throw new Error('File not found');

      // 2. Publish file metadata (CAS internally). updateFileMetadata zeroes the
      //    fileIpnsPrivateKey in its own finally (T-47-01) — do NOT zero it here.
      const { prunedCids } = await sdkCore.updateFileMetadata({
        fileIpnsPrivateKey: fileData.fileIpnsPrivateKey,
        fileMetaIpnsName: filePointer.fileMetaIpnsName,
        folderKey: folder.folderKey,
        currentMetadata: fileData.currentMetadata,
        updates: fileData.updates,
        createVersion: fileData.createVersion,
        maxVersionsPerFile: fileData.maxVersionsPerFile,
        ctx: this.ctx,
      });

      // 3. Touch the folder so other clients (e.g. FUSE mount) re-resolve the file.
      const baseChildren = [...folder.children];
      const nextChildren = folder.children.map((child) =>
        child.type === 'file' && child.id === fileId
          ? {
              ...child,
              modifiedAt: Date.now(),
              ...(fileData.migratedIpnsPrivateKeyEncrypted
                ? { ipnsPrivateKeyEncrypted: fileData.migratedIpnsPrivateKeyEncrypted }
                : {}),
            }
          : child
      );

      const { newSequenceNumber, publishedChildren } = await sdkCore.updateFolderMetadataAndPublish(
        {
          children: nextChildren,
          baseChildren,
          folderKey: folder.folderKey,
          ipnsPrivateKey: folder.ipnsKeypair.privateKey,
          ipnsName: parentIpnsName,
          sequenceNumber: folder.sequenceNumber,
          ctx: this.ctx,
        }
      );

      // 4. Adopt the merged published set (CR-01).
      folder.children = publishedChildren;
      folder.sequenceNumber = newSequenceNumber;
      folder.lastLoadedAt = Date.now();
      this.folderTree.set(parentIpnsName, folder);

      // 5. Emit folder:updated.
      this.emitter.emit({
        type: 'folder:updated',
        folderId: parentIpnsName,
        ipnsName: parentIpnsName,
        children: publishedChildren,
        sequenceNumber: newSequenceNumber,
      });

      return { prunedCids };
    });
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
  async restoreFileVersion(
    parentIpnsName: string,
    fileId: string,
    versionIndex: number,
    params: {
      fileIpnsPrivateKey: Uint8Array;
      currentMetadata: FileMetadata;
      updates: Partial<
        Pick<FileMetadata, 'cid' | 'fileKeyEncrypted' | 'fileIv' | 'size' | 'encryptionMode'>
      >;
      createVersion?: boolean;
      maxVersionsPerFile?: number;
      /** Hex-encoded re-wrapped IPNS key to persist on the FilePointer (lazy migration). */
      migratedIpnsPrivateKeyEncrypted?: string;
    }
  ): Promise<{ prunedCids: string[] }> {
    void versionIndex;
    return this.withOperation('restoreFileVersion', async () => {
      const folder = await this.requireFolder(parentIpnsName);

      const filePointer = folder.children.find(
        (c): c is FilePointer => c.type === 'file' && c.id === fileId
      );
      if (!filePointer) throw new Error('File not found');

      // 1. Publish file metadata (CAS internally). updateFileMetadata zeroes the
      //    fileIpnsPrivateKey in its own finally (T-47-01) — do NOT zero it here.
      const { prunedCids } = await sdkCore.updateFileMetadata({
        fileIpnsPrivateKey: params.fileIpnsPrivateKey,
        fileMetaIpnsName: filePointer.fileMetaIpnsName,
        folderKey: folder.folderKey,
        currentMetadata: params.currentMetadata,
        updates: params.updates,
        createVersion: params.createVersion ?? false,
        maxVersionsPerFile: params.maxVersionsPerFile,
        ctx: this.ctx,
      });

      // 2. Conditional folder publish for lazy IPNS-key migration only.
      await this.maybePublishKeyMigration(
        folder,
        parentIpnsName,
        fileId,
        params.migratedIpnsPrivateKeyEncrypted
      );

      // 3. Emit folder:updated from the (possibly advanced) folderTree snapshot.
      folder.lastLoadedAt = Date.now();
      this.folderTree.set(parentIpnsName, folder);
      this.emitter.emit({
        type: 'folder:updated',
        folderId: parentIpnsName,
        ipnsName: parentIpnsName,
        children: folder.children,
        sequenceNumber: folder.sequenceNumber,
      });

      return { prunedCids };
    });
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
  async deleteFileVersion(
    parentIpnsName: string,
    fileId: string,
    versionIndex: number,
    params: {
      fileIpnsPrivateKey: Uint8Array;
      currentMetadata: FileMetadata;
      updates: Partial<
        Pick<FileMetadata, 'cid' | 'fileKeyEncrypted' | 'fileIv' | 'size' | 'encryptionMode'>
      >;
      deletedCid?: string;
      maxVersionsPerFile?: number;
      /** Hex-encoded re-wrapped IPNS key to persist on the FilePointer (lazy migration). */
      migratedIpnsPrivateKeyEncrypted?: string;
    }
  ): Promise<{ deletedCid?: string; prunedCids: string[] }> {
    void versionIndex;
    return this.withOperation('deleteFileVersion', async () => {
      const folder = await this.requireFolder(parentIpnsName);

      const filePointer = folder.children.find(
        (c): c is FilePointer => c.type === 'file' && c.id === fileId
      );
      if (!filePointer) throw new Error('File not found');

      // 1. Publish file metadata (CAS internally). updateFileMetadata zeroes the
      //    fileIpnsPrivateKey in its own finally (T-47-01) — do NOT zero it here.
      //    Capture prunedCids: deleting a version never caps the history (count
      //    decreases), but a 409-conflict merge round can re-add versions past the
      //    cap, and those CIDs must be unpinned by the caller (matches replaceFile /
      //    restoreFileVersion).
      const { prunedCids } = await sdkCore.updateFileMetadata({
        fileIpnsPrivateKey: params.fileIpnsPrivateKey,
        fileMetaIpnsName: filePointer.fileMetaIpnsName,
        folderKey: folder.folderKey,
        currentMetadata: params.currentMetadata,
        updates: params.updates,
        createVersion: false,
        maxVersionsPerFile: params.maxVersionsPerFile,
        ctx: this.ctx,
      });

      // 2. Conditional folder publish for lazy IPNS-key migration only.
      await this.maybePublishKeyMigration(
        folder,
        parentIpnsName,
        fileId,
        params.migratedIpnsPrivateKeyEncrypted
      );

      // 3. Emit folder:updated from the (possibly advanced) folderTree snapshot.
      folder.lastLoadedAt = Date.now();
      this.folderTree.set(parentIpnsName, folder);
      this.emitter.emit({
        type: 'folder:updated',
        folderId: parentIpnsName,
        ipnsName: parentIpnsName,
        children: folder.children,
        sequenceNumber: folder.sequenceNumber,
      });

      return { deletedCid: params.deletedCid, prunedCids };
    });
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
  private async maybePublishKeyMigration(
    folder: FolderState,
    parentIpnsName: string,
    fileId: string,
    migratedIpnsPrivateKeyEncrypted?: string
  ): Promise<void> {
    if (!migratedIpnsPrivateKeyEncrypted) return;

    const baseChildren = [...folder.children];
    const nextChildren = folder.children.map((child) =>
      child.type === 'file' && child.id === fileId
        ? {
            ...child,
            modifiedAt: Date.now(),
            ipnsPrivateKeyEncrypted: migratedIpnsPrivateKeyEncrypted,
          }
        : child
    );

    const { newSequenceNumber, publishedChildren } = await sdkCore.updateFolderMetadataAndPublish({
      children: nextChildren,
      baseChildren,
      folderKey: folder.folderKey,
      ipnsPrivateKey: folder.ipnsKeypair.privateKey,
      ipnsName: parentIpnsName,
      sequenceNumber: folder.sequenceNumber,
      ctx: this.ctx,
    });

    folder.children = publishedChildren;
    folder.sequenceNumber = newSequenceNumber;
  }

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
  async downloadFromIpns(
    fileMetaIpnsName: string,
    folderKey: Uint8Array,
    onProgress?: DownloadProgressCallback
  ): Promise<Uint8Array> {
    return this.withOperation('downloadFromIpns', async () => {
      // 1. Resolve per-file IPNS to get FileMetadata
      const resolved = await sdkCore.resolveFileMetadata(fileMetaIpnsName, folderKey, this.ctx);

      // 2. Download and decrypt file content
      const plaintext = await sdkCore.downloadAndDecrypt({
        cid: resolved.metadata.cid,
        fileKeyEncrypted: resolved.metadata.fileKeyEncrypted,
        fileIv: resolved.metadata.fileIv,
        userPrivateKey: this.config.vaultKeypair.privateKey,
        encryptionMode: resolved.metadata.encryptionMode,
        ctx: this.ctx,
        onProgress,
      });

      this.emitter.emit({ type: 'file:downloaded', cid: resolved.metadata.cid });
      return plaintext;
    });
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
        this.fireAndForgetUnenroll(this.collectBinEntryIpnsNames(entry));
      }
    });
  }

  /**
   * Permanently delete all bin entries.
   */
  async emptyBin(): Promise<void> {
    return this.withOperation('emptyBin', async () => {
      if (!this.binState) throw new BinNotLoadedError();

      // Collect all IPNS names before emptying (includes subtree for folders)
      const ipnsNamesToUnenroll = this.binState.entries.flatMap((entry) =>
        this.collectBinEntryIpnsNames(entry)
      );

      const { updatedBinState } = await binOps.emptyBin({
        binState: this.binState,
        binCtx: this.getBinContext(),
      });

      this.binState = updatedBinState;
      this.emitter.emit({ type: 'bin:updated', entries: [] });

      // Fire-and-forget IPNS unenrollment for all emptied bin entries
      this.fireAndForgetUnenroll(ipnsNamesToUnenroll);
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
        this.fireAndForgetUnenroll(
          purgedEntries.flatMap((entry) => this.collectBinEntryIpnsNames(entry))
        );
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

  /**
   * Re-wrap keys for share recipients after adding items to a shared folder.
   *
   * @param coveringShares - Active shares covering the folder
   * @param newItems - New items whose keys need re-wrapping
   * @param addShareKeysFn - Function to add wrapped keys to a share via API
   */
  async reWrapForRecipients(
    coveringShares: SentShareInfo[],
    newItems: Array<{ keyType: 'file' | 'folder'; itemId: string; plaintextKey: Uint8Array }>,
    addShareKeysFn: (
      shareId: string,
      keys: Array<{ keyType: 'file' | 'folder'; itemId: string; encryptedKey: string }>
    ) => Promise<void>
  ): Promise<{ failedRecipients: string[] }> {
    return this.withOperation('reWrapForRecipients', async () => {
      return shareOps.reWrapForRecipients({
        coveringShares,
        newItems,
        addShareKeysFn,
      });
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
   */
  private buildSharedWriteContextFromState(
    state: SharedFolderState
  ): ReturnType<typeof shareOps.buildSharedWriteContext> {
    return shareOps.buildSharedWriteContext({
      ctx: this.ctx,
      folderKey: state.folderKey,
      ipnsPrivateKey: state.ipnsPrivateKey,
      ipnsName: state.ipnsName,
      sequenceNumber: state.sequenceNumber,
      children: state.children,
      ownerPublicKey: state.ownerPublicKey,
      recipientPublicKey: state.recipientPublicKey,
      shareId: state.shareId,
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
    result: { publishedChildren: FolderChild[]; newSequenceNumber: bigint }
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
   */
  async deleteFromSharedFolder(shareId: string, args: { itemId: string }): Promise<void> {
    return this.withOperation('deleteFromSharedFolder', async () => {
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
  async updateSharedFile(
    shareId: string,
    args: {
      filePointer: FilePointer;
      newContent: Uint8Array;
      getFileIpnsKeyFn: (itemId: string) => Promise<Uint8Array | null>;
    }
  ): Promise<void> {
    return this.withOperation('updateSharedFile', async () => {
      const state = this.requireSharedFolder(shareId);
      await shareOps.updateSharedFile({
        ctx: this.ctx,
        folderKey: state.folderKey,
        ownerPublicKey: state.ownerPublicKey,
        recipientPublicKey: state.recipientPublicKey,
        shareId: state.shareId,
        addShareKeysFn: state.addShareKeysFn,
        filePointer: args.filePointer,
        newContent: args.newContent,
        getFileIpnsKeyFn: args.getFileIpnsKeyFn,
      });
      // File-only publish: folder children/sequence unchanged. Emit so consumers
      // re-resolve the file metadata — but only if the share is still loaded (it
      // may have been unloaded during the in-flight publish).
      const live = this.sharedFolderTree.get(shareId);
      if (!live) return;
      this.emitter.emit({
        type: 'sharedFolder:updated',
        shareId,
        ipnsName: live.ipnsName,
        children: live.children,
        sequenceNumber: live.sequenceNumber,
      });
    });
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
        publishedChildren: result.metadata.children,
        newSequenceNumber: result.sequenceNumber,
      });
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
