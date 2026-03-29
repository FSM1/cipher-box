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
import type { PinningProvider } from '@cipherbox/sdk-core';
import * as sdkCore from '@cipherbox/sdk-core';
import { createAxiosInstance, ipnsControllerUnenrollBatch } from '@cipherbox/api-client';
import { clearBytes } from '@cipherbox/crypto';
import type { FolderChild, FolderEntry, FilePointer, BinEntry } from '@cipherbox/core';
import type { CipherBoxClientConfig, FolderState } from './types';
import { SdkEventEmitter, type SdkEvent, type SdkEventHandler } from './events';
import { FolderTree } from './state/folder-tree';
import { KeyCache } from './state/key-cache';
import * as binOps from './bin';
import type { BinState } from './bin';
import * as shareOps from './share';
import type { SentShareInfo } from './share';

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
  private keyCache: KeyCache;
  private binState: BinState | null = null;
  /** BYO-IPFS external pinning provider (null when mode is 'cipherbox') */
  private externalProvider: PinningProvider | null = null;
  /** Internal copies of key material — zeroed on destroy() without affecting caller buffers */
  private internalVaultKeypair: { publicKey: Uint8Array; privateKey: Uint8Array };
  private internalRootFolderKey: Uint8Array;

  constructor(config: CipherBoxClientConfig) {
    // Defensive copy of key material so destroy() only zeroes our copies
    this.internalVaultKeypair = {
      publicKey: new Uint8Array(config.vaultKeypair.publicKey),
      privateKey: new Uint8Array(config.vaultKeypair.privateKey),
    };
    this.internalRootFolderKey = new Uint8Array(config.rootFolderKey);
    this.config = {
      ...config,
      vaultKeypair: this.internalVaultKeypair,
      rootFolderKey: this.internalRootFolderKey,
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
    this.keyCache.clear();
    this.emitter.removeAll();
    // Zero internal key copies (defense-in-depth; JS GC may retain copies)
    // Only zeroes our copies, not the caller-provided buffers
    this.internalVaultKeypair.privateKey.fill(0);
    this.internalVaultKeypair.publicKey.fill(0);
    this.internalRootFolderKey.fill(0);
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
   * Used by ensureFolderRegistered to preserve SDK's correct IPNS key
   * when the store has an empty placeholder (SDK-created folders store
   * keys internally, not in Zustand).
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
      const parent = this.folderTree.get(parentIpnsName);
      if (!parent) throw new Error('Parent folder not loaded');

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
        const updatedChildren: FolderChild[] = [...parent.children, folder];

        // 4. Update parent metadata and publish
        const { newSequenceNumber } = await sdkCore.updateFolderMetadataAndPublish({
          children: updatedChildren,
          folderKey: parent.folderKey,
          ipnsPrivateKey: parent.ipnsKeypair.privateKey,
          ipnsName: parentIpnsName,
          sequenceNumber: parent.sequenceNumber,
          ctx: this.ctx,
          encryptedIpnsPrivateKey: encryptedIpnsPrivateKey,
          keyEpoch,
        });

        // 5. Update parent state
        parent.children = updatedChildren;
        parent.sequenceNumber = newSequenceNumber;
        parent.lastLoadedAt = Date.now();
        this.folderTree.set(parentIpnsName, parent);

        // 6. Publish empty metadata for the new subfolder
        await sdkCore.updateFolderMetadataAndPublish({
          children: [],
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
          children: updatedChildren,
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
      const folder = this.folderTree.get(folderIpnsName);
      if (!folder) throw new Error('Folder not loaded');

      // 1. Rename in metadata (pure operation)
      const { updatedChildren } = sdkCore.renameInFolder({
        children: folder.children,
        childId,
        newName,
      });

      // 2. Publish updated metadata
      const { newSequenceNumber } = await sdkCore.updateFolderMetadataAndPublish({
        children: updatedChildren,
        folderKey: folder.folderKey,
        ipnsPrivateKey: folder.ipnsKeypair.privateKey,
        ipnsName: folderIpnsName,
        sequenceNumber: folder.sequenceNumber,
        ctx: this.ctx,
      });

      // 3. Update internal state
      folder.children = updatedChildren;
      folder.sequenceNumber = newSequenceNumber;
      folder.lastLoadedAt = Date.now();
      this.folderTree.set(folderIpnsName, folder);

      // 4. Emit update event
      this.emitter.emit({
        type: 'folder:updated',
        folderId: folderIpnsName,
        ipnsName: folderIpnsName,
        children: updatedChildren,
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
      const source = this.folderTree.get(sourceIpnsName);
      const dest = this.folderTree.get(destIpnsName);
      if (!source) throw new Error('Source folder not loaded');
      if (!dest) throw new Error('Destination folder not loaded');

      // 1. Compute updated children for both folders (pure operation)
      const { updatedSourceChildren, updatedDestChildren } = sdkCore.moveItem({
        sourceChildren: source.children,
        destChildren: dest.children,
        childId,
      });

      // 2. Publish destination first (add-before-remove for crash safety)
      const destResult = await sdkCore.updateFolderMetadataAndPublish({
        children: updatedDestChildren,
        folderKey: dest.folderKey,
        ipnsPrivateKey: dest.ipnsKeypair.privateKey,
        ipnsName: destIpnsName,
        sequenceNumber: dest.sequenceNumber,
        ctx: this.ctx,
      });

      // 3. Publish source (remove)
      const sourceResult = await sdkCore.updateFolderMetadataAndPublish({
        children: updatedSourceChildren,
        folderKey: source.folderKey,
        ipnsPrivateKey: source.ipnsKeypair.privateKey,
        ipnsName: sourceIpnsName,
        sequenceNumber: source.sequenceNumber,
        ctx: this.ctx,
      });

      // 4. Update internal state
      source.children = updatedSourceChildren;
      source.sequenceNumber = sourceResult.newSequenceNumber;
      dest.children = updatedDestChildren;
      dest.sequenceNumber = destResult.newSequenceNumber;
      this.folderTree.set(sourceIpnsName, source);
      this.folderTree.set(destIpnsName, dest);

      // 5. Emit events for both folders
      this.emitter.emit({
        type: 'folder:updated',
        folderId: sourceIpnsName,
        ipnsName: sourceIpnsName,
        children: updatedSourceChildren,
        sequenceNumber: sourceResult.newSequenceNumber,
      });
      this.emitter.emit({
        type: 'folder:updated',
        folderId: destIpnsName,
        ipnsName: destIpnsName,
        children: updatedDestChildren,
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
      const folder = this.folderTree.get(folderIpnsName);
      if (!folder) throw new Error('Folder not loaded');

      // 1. Remove from metadata (pure operation)
      const { updatedChildren, removedItem } = sdkCore.deleteFromFolder({
        children: folder.children,
        childId,
      });

      // 2. Publish updated metadata
      const { newSequenceNumber } = await sdkCore.updateFolderMetadataAndPublish({
        children: updatedChildren,
        folderKey: folder.folderKey,
        ipnsPrivateKey: folder.ipnsKeypair.privateKey,
        ipnsName: folderIpnsName,
        sequenceNumber: folder.sequenceNumber,
        ctx: this.ctx,
      });

      // 3. Update internal state
      folder.children = updatedChildren;
      folder.sequenceNumber = newSequenceNumber;
      folder.lastLoadedAt = Date.now();
      this.folderTree.set(folderIpnsName, folder);

      // 4. Emit update event
      this.emitter.emit({
        type: 'folder:updated',
        folderId: folderIpnsName,
        ipnsName: folderIpnsName,
        children: updatedChildren,
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
      const folder = this.folderTree.get(folderIpnsName);
      if (!folder) throw new Error('Folder not loaded');

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

        const { newSequenceNumber } = folderResult.value;

        // 4. Update internal state
        folder.children = updatedChildren;
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
          children: updatedChildren,
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
      if (!this.binState) throw new BinNotLoadedError();

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
      const folder = this.folderTree.get(folderIpnsName);
      if (!folder) throw new Error('Folder not loaded');

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

// ---- Encryption mode selection ----

/** MIME types eligible for CTR streaming encryption */
const STREAMING_MIME_TYPES = new Set([
  'video/mp4',
  'video/webm',
  'audio/mpeg',
  'audio/mp4',
  'audio/webm',
  'audio/ogg',
  'audio/aac',
]);

/** Minimum file size (bytes) to use CTR mode: 256KB */
const CTR_SIZE_THRESHOLD = 256 * 1024;

/**
 * Select encryption mode based on MIME type and size.
 * Media files above 256KB use CTR for random-access streaming decryption.
 */
function selectEncryptionMode(mimeType: string, size: number): 'GCM' | 'CTR' {
  if (STREAMING_MIME_TYPES.has(mimeType) && size > CTR_SIZE_THRESHOLD) {
    return 'CTR';
  }
  return 'GCM';
}
