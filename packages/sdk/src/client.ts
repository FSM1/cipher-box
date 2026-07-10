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
import type { TeeKeys, ConnectionTestResult } from '@cipherbox/sdk-core';
import * as sdkCore from '@cipherbox/sdk-core';
import { selectEncryptionMode } from '@cipherbox/sdk-core';
import {
  createAxiosInstance,
  ipnsControllerUnenrollBatch,
  sharesControllerRevokeForItems,
} from '@cipherbox/api-client';
import {
  clearBytes,
  unwrapKey,
  wrapKey,
  hexToBytes,
  bytesToHex,
  deriveEd25519PublicKey,
  generateEd25519Keypair,
  generateRandomBytes,
  deriveIpnsName,
  decryptAesGcm,
  decryptAesCtr,
} from '@cipherbox/crypto';
import pLimit from 'p-limit';
import type {
  BinEntry,
  SealedChildRef,
  WriteChildRef,
  PublishedNode,
  Node as CoreNode,
  NodeContent,
  NodeKind,
  EncryptionMode,
} from '@cipherbox/core';
import {
  sealChildReadKey,
  sealChildWriteKey,
  sealNode,
  unsealChildReadKey,
  unsealChildWriteKey,
  unsealNode,
} from '@cipherbox/core';
// D-07 full-boundary facade primitives (68.2-04): auth-bootstrap/vault crypto
// (useAuth.ts) and device-registry crypto (device-registry.service.ts) --
// these are the @cipherbox/core symbols the web imports at runtime today;
// mediating them here lets the cutover wave (Plan 10) stop importing
// @cipherbox/core directly for vault/registry operations.
import {
  initializeVault,
  encryptVaultKeys,
  serializeVaultBlobV3,
  deserializeVaultBlobV3,
  deriveRegistryIpnsKeypair,
  encryptRegistry,
  decryptRegistry,
} from '@cipherbox/core';
import type { VaultInit, DeviceRegistry } from '@cipherbox/core';
import type {
  CipherBoxClientConfig,
  FolderState,
  SharedFolderState,
  RotationClientCallbacks,
} from './types';
import { SdkEventEmitter, type SdkEvent, type SdkEventHandler } from './events';
import { FolderTree } from './state/folder-tree';
import { SharedFolderTree } from './state/shared-folder-tree';
import { KeyCache } from './state/key-cache';
import * as binOps from './bin';
import type { BinState } from './bin';
import * as shareOps from './share';
import { resolveChildren, type ResolvedChild } from './folder-listing';

/** Maximum concurrent encrypt+pin operations for batch uploads. */
const UPLOAD_CONCURRENCY = 3;

/**
 * Maximum concurrent on-demand IPNS subtree collections for fire-and-forget
 * unenroll. Bounds the request fan-out when emptying/purging a bin with many
 * top-level entries (WR-04). Each collection still walks its own subtree
 * sequentially, so this caps the number of subtrees fetched in parallel.
 */
const UNENROLL_COLLECT_CONCURRENCY = 8;

/**
 * Decode a base64 string to raw bytes (68.2-08 hoist from
 * `apps/web/src/hooks/useSharedNavigationActions.ts` -- decodes
 * `NodeContent.fileIv`, which is base64-encoded under node/v3, unlike the
 * legacy hex-encoded fileIv `sdkCore.downloadAndDecrypt` expects).
 */
function sharedFileBase64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encode raw bytes to base64 (68.2-08 hoist). Bridges the web's hex-encoded
 * `encryptedReadKey` (API DTO contract) into `navigateReadChain`'s base64
 * contract (sdk-core's own `issueReadGrant` produces base64 -- the two
 * encodings diverge at the API boundary).
 */
function sharedFileBytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

/** Thrown when a bin operation is attempted before loadBin() has been called. */
export class BinNotLoadedError extends Error {
  constructor() {
    super('Bin not loaded');
    this.name = 'BinNotLoadedError';
  }
}

/**
 * Thrown when a mutation's reconcile-before-publish check (SC#3 / D-04) finds
 * the freshly-resolved network `sequenceNumber` disagrees with the in-memory
 * `FolderTree` entry -- in EITHER direction (network ahead OR local ahead).
 * The mutation defers (throws) rather than publishing a metadata update or a
 * rotation against possibly-superseded state. "Defer, never skip" -- callers
 * should re-load the folder and retry.
 */
export class ReconcileStaleError extends Error {
  /** In-memory `FolderTree` sequenceNumber the mutation expected to publish against. */
  readonly localSequence: bigint;
  /** Freshly-resolved network sequenceNumber that disagreed with `localSequence`. */
  readonly networkSequence: bigint;

  constructor(ipnsName: string, localSequence: bigint, networkSequence: bigint) {
    super(
      `Reconcile stale: folder ${ipnsName} local sequenceNumber ${localSequence} does not match ` +
        `network sequenceNumber ${networkSequence} -- deferring mutation (SC#3 / D-04)`
    );
    this.name = 'ReconcileStaleError';
    // Exposed so callers (useMutationFailureUx's D-05 classifier) can tell a
    // genuine concurrent-update defer (network AHEAD of local -- SC#3/D-04,
    // retry) apart from a stale/relay-replayed record (network BEHIND local
    // -- a rejection the durable ROT-07 floor may not catch when the replayed
    // seq exactly matches the last-recorded floor; see Gap 4 / 68.1-21).
    this.localSequence = localSequence;
    this.networkSequence = networkSequence;
  }
}

/**
 * Default rotation callbacks used when a `CipherBoxClient` is constructed
 * without `config.rotationCallbacks`. Every callback is a safe no-op so
 * `hasCoveringGrant` always finds zero coverage and `maybeRotateOnScopeExit`
 * never invokes `deps.rotate` -- i.e. an unconfigured client performs zero
 * rotation, identical to pre-Phase-68 behavior. Concrete web callbacks are
 * wired in Phase 68-08.
 */
const NOOP_ROTATION_CALLBACKS: RotationClientCallbacks = {
  getActiveGrantRootIpnsNames: async () => new Set<string>(),
  getLocalGrantRecord: () => null,
  persistJob: () => {},
};

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
  /**
   * In-SDK cache of resolved listings (SDK-READ-02, D-02), keyed by IPNS
   * name and invalidated by sequenceNumber -- the clock. A folder and any
   * shared-folder depth reaching the SAME ipnsName share one cache entry
   * (ResolvedChild[] is fully determined by the folder's own content, not
   * the access path that reached it).
   */
  private listingCache: Map<string, { sequenceNumber: bigint; children: ResolvedChild[] }> =
    new Map();
  /**
   * In-flight dedup for `reresolveFolderInPlace` (68.2-13, T-68.2-13-04):
   * coalesces concurrent `{ forceResolve: true }` calls for the SAME
   * ipnsName (e.g. a nav re-resolve firing alongside the 30s poll leg) to a
   * single network resolve.
   */
  private reresolveInFlight: Map<string, Promise<FolderState | null>> = new Map();
  private keyCache: KeyCache;
  private binState: BinState | null = null;
  /** BYO-IPFS external pinning provider (null when mode is 'cipherbox') */
  private externalProvider: PinningProvider | null = null;
  /** Internal copies of key material — zeroed on destroy() without affecting caller buffers */
  private internalVaultKeypair: { publicKey: Uint8Array; privateKey: Uint8Array };
  private internalRootFolderKey: Uint8Array;
  /**
   * Internal copy of the root write key, or null when not configured (D-03).
   * Required alongside internalRootIpnsKeypair for ensureFolderLoaded self-bootstrap
   * to recover owned write-bodies; absent when the host hasn't wired rootWriteKey yet
   * (Phase 68.1-03).
   */
  private internalRootWriteKey: Uint8Array | null = null;
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
    if (config.rootWriteKey) {
      this.internalRootWriteKey = new Uint8Array(config.rootWriteKey);
    }
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
      rootWriteKey: this.internalRootWriteKey ?? undefined,
      rootIpnsKeypair: this.internalRootIpnsKeypair ?? undefined,
      rotationCallbacks: config.rotationCallbacks ?? NOOP_ROTATION_CALLBACKS,
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
   * DFS walk of a resolved node's children, returning every descendant's own
   * IPNS name (the node itself is NOT included — callers prepend it).
   *
   * Best-effort (T-68.1-02-01): an unreadable descendant is logged and
   * skipped rather than throwing, so a bad hop never wedges the fire-and-forget
   * unenroll/unpin flow on an otherwise-normal delete/empty-bin. A descendant
   * that fails to resolve/unseal still contributes its own `childRef.ipnsName`
   * to the result (best-effort unenroll of the leaf itself) but is not
   * descended into further.
   *
   * Bounded to `UNENROLL_COLLECT_CONCURRENCY` concurrent hops (T-68.1-02-01).
   * Zeroes every minted childReadKey; never zeroes `nodeReadKey` (caller-owned, D-09).
   */
  private async collectDescendantIpnsNames(
    nodeReadKey: Uint8Array,
    nodeChildren: SealedChildRef[]
  ): Promise<string[]> {
    const limit = pLimit(UNENROLL_COLLECT_CONCURRENCY);
    const results = await Promise.all(
      nodeChildren.map((childRef) =>
        limit(async (): Promise<string[]> => {
          try {
            const childResolved = await this.resolvePublishedNode(childRef.ipnsName);
            if (!childResolved) return [childRef.ipnsName];
            if (
              childResolved.published.kind !== 'folder' &&
              childResolved.published.kind !== 'root'
            ) {
              return [childRef.ipnsName];
            }

            let childReadKey: Uint8Array | null = null;
            try {
              childReadKey = await unsealChildReadKey(
                childRef.readKeySealed,
                nodeReadKey,
                childResolved.published.id,
                childResolved.published.kind,
                childRef.generation
              );
              const childNode = await unsealNode(childResolved.published, childReadKey);
              const nested = await this.collectDescendantIpnsNames(
                childReadKey,
                childNode.children ?? []
              );
              return [childRef.ipnsName, ...nested];
            } finally {
              childReadKey?.fill(0);
            }
          } catch (err) {
            console.warn(
              `[CipherBox] subtree collect: unreadable descendant ${childRef.ipnsName}:`,
              err
            );
            return [childRef.ipnsName];
          }
        })
      )
    );
    return results.flat();
  }

  /**
   * Extract IPNS names from a removed SealedChildRef (file or folder subtree).
   *
   * Resolves the item's own PublishedNode to learn its plaintext id/kind, then
   * (for a folder/root) recovers its readKey from `item.readKeySealed` under
   * `parentReadKey` and walks its descendants. A file leaf contributes only
   * its own ipnsName. Best-effort (T-68.1-02-01): an unresolvable/unreadable
   * item still contributes its own ipnsName so unenroll/unpin proceeds.
   *
   * @param parentReadKey - readKey of the folder `item` was just removed from
   *   (caller-owned — NOT zeroed here, D-09).
   */
  private async collectRemovedItemIpnsNames(
    item: SealedChildRef,
    parentReadKey: Uint8Array
  ): Promise<string[]> {
    try {
      const resolved = await this.resolvePublishedNode(item.ipnsName);
      if (!resolved) return [item.ipnsName];
      if (resolved.published.kind !== 'folder' && resolved.published.kind !== 'root') {
        return [item.ipnsName];
      }

      let itemReadKey: Uint8Array | null = null;
      try {
        itemReadKey = await unsealChildReadKey(
          item.readKeySealed,
          parentReadKey,
          resolved.published.id,
          resolved.published.kind,
          item.generation
        );
        const itemNode = await unsealNode(resolved.published, itemReadKey);
        const descendants = await this.collectDescendantIpnsNames(
          itemReadKey,
          itemNode.children ?? []
        );
        return [item.ipnsName, ...descendants];
      } finally {
        itemReadKey?.fill(0);
      }
    } catch (err) {
      console.warn(`[CipherBox] subtree collect: unreadable removed item ${item.ipnsName}:`, err);
      return [item.ipnsName];
    }
  }

  /**
   * Extract IPNS names from a BinEntry (node ref and/or folder subtree).
   *
   * Reads from `entry.nodeRef` / `entry.nodeReadKey` / `entry.nodeIpnsName`
   * (`filePointer`/`folderEntry` were removed — [62-05]). A folder/root entry
   * is walked via `collectDescendantIpnsNames` using the node's own children
   * (already plaintext inside `nodeRef`, since the bin blob itself is
   * ECIES-encrypted to the owner) and its captured `nodeReadKey`. A file entry
   * or an entry missing the required fields (legacy/incomplete row) contributes
   * only its own ipnsName (or nothing, if even that is absent).
   */
  private async collectBinEntryIpnsNames(entry: BinEntry): Promise<string[]> {
    if (!entry.nodeIpnsName) return [];
    if (!entry.nodeRef || !entry.nodeReadKey) return [entry.nodeIpnsName];
    if (entry.nodeRef.kind !== 'folder' && entry.nodeRef.kind !== 'root') {
      return [entry.nodeIpnsName];
    }
    try {
      const descendants = await this.collectDescendantIpnsNames(
        entry.nodeReadKey,
        entry.nodeRef.children ?? []
      );
      return [entry.nodeIpnsName, ...descendants];
    } catch (err) {
      console.warn(`[CipherBox] subtree collect: bin entry ${entry.id} descend failed:`, err);
      return [entry.nodeIpnsName];
    }
  }

  /**
   * Destroy the client, clearing all sensitive state.
   * After calling destroy(), the client instance should not be reused.
   */
  destroy(): void {
    this.folderTree.clear();
    this.sharedFolderTree.clear();
    this.keyCache.clear();
    // Drop the SDK-owned read caches so no resolved listing (private folder
    // structure) or in-flight re-resolve closure survives after destroy().
    this.listingCache.clear();
    this.reresolveInFlight.clear();
    this.emitter.removeAll();
    // Zero internal key copies (defense-in-depth; JS GC may retain copies)
    // Only zeroes our copies, not the caller-provided buffers
    this.internalVaultKeypair.privateKey.fill(0);
    this.internalVaultKeypair.publicKey.fill(0);
    this.internalRootFolderKey.fill(0);
    if (this.internalRootWriteKey) {
      this.internalRootWriteKey.fill(0);
    }
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
   * @param writeKey - Optional 32-byte AES-256 write key (D-03). Omitting falls back
   *   to a zero-filled key (legacy compatibility) — callers that need write-body
   *   preservation on republish (rename/move/delete/restore) should supply the real
   *   writeKey recovered via ensureFolderLoaded or createSubfolder.
   */
  registerFolder(
    ipnsName: string,
    folderKey: Uint8Array,
    ipnsKeypair: { publicKey: Uint8Array; privateKey: Uint8Array },
    children: SealedChildRef[],
    sequenceNumber: bigint,
    nodeId?: string,
    nodeGeneration?: number,
    writeKey?: Uint8Array
  ): void {
    // Defensive copy so destroy() -> folderTree.clear() doesn't zero caller buffers
    this.folderTree.set(ipnsName, {
      ipnsName,
      folderKey: new Uint8Array(folderKey),
      writeKey: new Uint8Array(writeKey ?? new Uint8Array(32)),
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
   * @param writeKey - Optional 32-byte AES-256 write key (D-03). Omitting falls back to
   *   a zero-filled key (legacy compatibility, matching registerFolder) unless an
   *   already-loaded folderTree entry carries a real writeKey, which is preserved.
   * @returns The loaded folder state, or null if IPNS record not found
   */
  async loadFolder(
    ipnsName: string,
    folderKey: Uint8Array,
    ipnsKeypair: { publicKey: Uint8Array; privateKey: Uint8Array },
    writeKey?: Uint8Array
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
          children: await this.resolveListingChildren(
            existing.children,
            existing.folderKey,
            ipnsName,
            existing.sequenceNumber
          ),
          sequenceNumber: existing.sequenceNumber,
        });
        return existing;
      }

      const state: FolderState = {
        ipnsName,
        // Preserve an already-recovered real writeKey across a reload rather than
        // clobbering it with the zero-fallback (D-03).
        writeKey: new Uint8Array(writeKey ?? existing?.writeKey ?? new Uint8Array(32)),
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
        children: await this.resolveListingChildren(
          state.children,
          state.folderKey,
          ipnsName,
          state.sequenceNumber
        ),
        sequenceNumber: result.sequenceNumber,
      });

      return state;
    });
  }

  /**
   * Resolve an IPNS name to its raw PublishedNode envelope + current sequenceNumber.
   * Returns null when the IPNS record is absent (structurally unresolvable hop) —
   * NOT when a crypto/AEAD verification subsequently fails on the caller side.
   *
   * Threads `signatureVerified` from `sdkCore.resolveIpnsRecord` (68.2-01 —
   * previously discarded) so read-path callers (`dfsFindFolder`,
   * `ensureRootFolderState`) can fail closed on an unverified record BEFORE
   * gating it through `RotationHighWater.enforceResolved` (ROT-07).
   */
  private async resolvePublishedNode(ipnsName: string): Promise<{
    published: PublishedNode;
    sequenceNumber: bigint;
    signatureVerified: boolean;
  } | null> {
    const resolved = await sdkCore.resolveIpnsRecord(ipnsName, this.ctx);
    if (!resolved) return null;
    const raw = await sdkCore.fetchFromIpfs(this.ctx, resolved.cid);
    const published = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
    return {
      published,
      sequenceNumber: resolved.sequenceNumber,
      signatureVerified: resolved.signatureVerified,
    };
  }

  /**
   * Resolve one folder-listing CHILD's PublishedNode through the durable
   * ROT-07 anti-rollback gate (T-68.2-01 / SDK-READ-02) -- the single gated
   * read entrypoint `folder-listing.ts`'s `resolveChildren` is injected with
   * (D-05).
   *
   * This is a STANDALONE per-child listing resolve, distinct from
   * `dfsFindFolder`'s per-hop gate: `dfsFindFolder` gates a child only while
   * searching for a specific DESCENDANT target and discards the result for
   * every non-matching (including every file) child; every immediate child
   * of a LISTED folder is gated here, file children included.
   *
   * Fail-closed and generation-sourcing rules mirror `dfsFindFolder`'s gate
   * exactly (68.2-01): fail closed on `!signatureVerified` BEFORE any floor
   * mutation, guard `Number.MAX_SAFE_INTEGER` overflow, and source
   * `generation`/`versionFloor` from `childRef` (the PARENT's SealedChildRef
   * mirror) -- NEVER the child's own envelope generation (Pitfall 3).
   */
  private async gatedResolveChild(
    childRef: SealedChildRef
  ): Promise<{ published: PublishedNode; sequenceNumber: bigint } | null> {
    const resolved = await this.resolvePublishedNode(childRef.ipnsName);
    if (!resolved) return null; // structurally unresolvable hop -- skip, try siblings

    if (this.config.rotationHighWater) {
      if (!resolved.signatureVerified) {
        throw new Error(
          `IPNS resolve for ${childRef.ipnsName} returned an unverified record -- refusing to gate durable floors on it`
        );
      }
      if (
        resolved.sequenceNumber > BigInt(Number.MAX_SAFE_INTEGER) ||
        childRef.versionFloor > BigInt(Number.MAX_SAFE_INTEGER)
      ) {
        throw new Error(
          `IPNS sequence number for ${childRef.ipnsName} exceeds Number.MAX_SAFE_INTEGER -- refusing lossy floor conversion`
        );
      }
      await this.config.rotationHighWater.enforceResolved({
        nodeId: childRef.ipnsName,
        seq: Number(resolved.sequenceNumber),
        generation: childRef.generation,
        versionFloor: Number(childRef.versionFloor),
      });
    }

    return { published: resolved.published, sequenceNumber: resolved.sequenceNumber };
  }

  /**
   * Resolve a single child's OWN readKey + plaintext node identity by
   * walking one hop of the read-chain (D-07 full-boundary facade, 68.2-07
   * Rule-2 addition).
   *
   * Mirrors `resolveChildren`'s (folder-listing.ts) per-child resolve+unseal
   * step, but returns the raw derived `readKey` + full node identity instead
   * of the display-only `ResolvedChild` projection. This is the facade
   * replacement for `apps/web/src/lib/crypto/key-wrapping.ts`'s
   * `resolveChildNodeIdentity` (used by ShareDialog / invite.service to
   * derive a shared item's OWN readKey + nodeId/generation before issuing a
   * grant -- the grant root IS the shared item, not its parent).
   *
   * Routes through the same gated resolve (`gatedResolveChild`, ROT-07) as
   * every other per-child listing hop (D-05 single gated read entrypoint).
   *
   * @param childRef - The child's SealedChildRef as it lives in the parent's children array
   * @param parentReadKey - The parent node's decrypted readKey (unwrapping key)
   * @security Does NOT zero `parentReadKey` -- caller is the terminal owner (D-09).
   *   The returned `readKey` is minted by this call; the caller becomes its
   *   terminal owner and must zero it on its own lifecycle boundary.
   */
  async resolveChildIdentity(
    childRef: SealedChildRef,
    parentReadKey: Uint8Array
  ): Promise<{
    readKey: Uint8Array;
    nodeId: string;
    kind: NodeKind;
    generation: number;
    published: PublishedNode;
  }> {
    return this.withOperation('resolveChildIdentity', async () => {
      const resolved = await this.gatedResolveChild(childRef);
      if (!resolved) {
        throw new Error(`resolveChildIdentity: IPNS record not found for ${childRef.ipnsName}`);
      }
      const { published } = resolved;
      const readKey = await unsealChildReadKey(
        childRef.readKeySealed,
        parentReadKey,
        published.id,
        published.kind,
        childRef.generation // parent-mirror generation-source rule -- never published.generation
      );
      return {
        readKey,
        nodeId: published.id,
        kind: published.kind,
        generation: published.generation,
        published,
      };
    });
  }

  /**
   * Resolve (or return the cached) `ResolvedChild[]` for a folder's sealed
   * children, cached in `listingCache` keyed by `ipnsName` and invalidated
   * by `sequenceNumber` -- the clock (D-02). A repeat call for the same
   * `ipnsName` at an UNCHANGED `sequenceNumber` returns the cached listing
   * without re-resolving any child.
   */
  private async resolveListingChildren(
    children: SealedChildRef[],
    parentReadKey: Uint8Array,
    ipnsName: string,
    sequenceNumber: bigint
  ): Promise<ResolvedChild[]> {
    const cached = this.listingCache.get(ipnsName);
    if (cached && cached.sequenceNumber === sequenceNumber) {
      return cached.children;
    }
    const resolved = await resolveChildren(children, parentReadKey, (childRef) =>
      this.gatedResolveChild(childRef)
    );
    // Do NOT cache a PARTIAL listing. `resolveChildren` skips any child it
    // can't currently resolve (transient network error, ROT-07 rejection, bad
    // AEAD -- as well as a genuinely revoked/absent hop). Caching an incomplete
    // result at this sequenceNumber would pin it until a remote write advances
    // the sequence or the client reloads -- even the `forceResolve` poll/nav
    // paths reuse a same-sequence entry (they refresh the folder's OWN sequence,
    // not its children). Skipping the cache-set when a child was dropped lets a
    // later resolve reattempt it and self-heal on network recovery.
    if (resolved.length === children.length) {
      this.listingCache.set(ipnsName, { sequenceNumber, children: resolved });
    }
    return resolved;
  }

  /**
   * List a folder's children as `ResolvedChild[]` (SDK-READ-02, SC#2) --
   * resolved once per folder load through the gated read path (68.2-01) and
   * cached in the SDK keyed by `ipnsName` (D-02). The web renders directly
   * from this result with no web-side per-child resolve or cache.
   *
   * Self-bootstraps via `ensureFolderLoaded` (68.2-01 gated), so a cold
   * client can call this directly without a prior `loadFolder`/
   * `registerFolder`, exactly like every other `ensureFolderLoaded`-backed
   * mutation chokepoint.
   *
   * `opts.forceResolve` (68.2-13, SDK-READ-03 / SC#5) threads through to
   * `ensureFolderLoaded` so an already-loaded folder's stored sequence
   * advances from network truth BEFORE this method's own
   * `resolveListingChildren` cache check runs -- closing the
   * self-referential cache-clock gap where the check compared the incoming
   * sequence against the SAME stale value the short-circuit had just
   * returned.
   */
  async listFolder(ipnsName: string, opts?: { forceResolve?: boolean }): Promise<ResolvedChild[]> {
    return this.withOperation('listFolder', async () => {
      const folder = await this.ensureFolderLoaded(ipnsName, opts);
      if (!folder) return [];
      return this.resolveListingChildren(
        folder.children,
        folder.folderKey,
        ipnsName,
        folder.sequenceNumber
      );
    });
  }

  /**
   * Return a folder's full decoded metadata (the decrypted `Node`,
   * including its raw `SealedChildRef[]` children) by delegating to the
   * gated `ensureFolderLoaded` path (D-05 single gated read entrypoint).
   *
   * Mediated replacement for the web's direct `sdkCore.fetchAndDecryptMetadata`
   * call (RESEARCH Code Examples, `useFileBrowserActions.ts`/`folder-helpers.ts`)
   * — callers that need the folder's own metadata fields (not just its
   * resolved children) should use this instead of `listFolder`.
   *
   * @param ipnsName - IPNS name of the folder
   * @returns The decrypted `Node`, or `null` if the folder cannot be loaded
   *   (matches `ensureFolderLoaded`'s not-found contract)
   */
  async getFolderMetadata(ipnsName: string): Promise<CoreNode | null> {
    return this.withOperation('getFolderMetadata', async () => {
      const folder = await this.ensureFolderLoaded(ipnsName);
      return folder?.metadata ?? null;
    });
  }

  /**
   * List a shared folder's children as `ResolvedChild[]` for an
   * INTERMEDIATE folder reached by descending `path` (a sequence of child
   * `ipnsName`s) from the already-loaded share root/depth in
   * `sharedFolderTree` (SDK-READ-02, SC#2).
   *
   * `path` walks one hop at a time -- gated-resolve the hop's
   * PublishedNode, unseal its readKey under the CURRENT depth's readKey
   * (generation-source rule: `childRef.generation`, the PARENT mirror,
   * §2.6), unseal its Node to recover the next depth's children -- hoisted
   * from `apps/web/src/hooks/useSharedNavigationActions.ts`'s
   * `navigateToSubfolder` walk (Pitfall 1: `navigateReadChain` forces a
   * `kind: 'file'` leaf and cannot render an intermediate folder, so this
   * walk is NOT built on top of it). This method never mutates
   * `sharedFolderTree` -- listing is read-only; navigation commits still go
   * through the existing `navigateToShare`/`navigateToSubfolder` web flow.
   *
   * Zeroing: each hop's minted readKey is the terminal owner's
   * responsibility once superseded by the next hop (or once the final
   * listing resolve completes) -- never the original `sharedFolderTree`
   * entry's `folderKey` (caller/tree-owned, D-09).
   *
   * @throws if `shareId` has no loaded `SharedFolderState`, if a hop in
   *   `path` is not found among the current depth's children, or if a hop
   *   is no longer resolvable (revoked).
   */
  async listSharedFolder(shareId: string, path: string[] = []): Promise<ResolvedChild[]> {
    return this.withOperation('listSharedFolder', async () => {
      const state = this.sharedFolderTree.get(shareId);
      if (!state) {
        throw new Error(`Shared folder not loaded: ${shareId}`);
      }

      let currentChildren = state.children;
      let currentReadKey = state.folderKey; // caller/tree-owned -- never zeroed
      let currentIpnsName = state.ipnsName;
      let currentSequenceNumber = state.sequenceNumber;
      let mintedReadKey: Uint8Array | null = null;

      try {
        for (const targetIpnsName of path) {
          const childRef = currentChildren.find((c) => c.ipnsName === targetIpnsName);
          if (!childRef) {
            throw new Error(
              `Shared subfolder not found in listSharedFolder path: ${targetIpnsName}`
            );
          }
          const childResolved = await this.gatedResolveChild(childRef);
          if (!childResolved) {
            throw new Error(`Shared subfolder is no longer available (revoked): ${targetIpnsName}`);
          }
          const childReadKey = await unsealChildReadKey(
            childRef.readKeySealed,
            currentReadKey,
            childResolved.published.id,
            childResolved.published.kind,
            childRef.generation // parent mirror -- NEVER childResolved.published.generation
          );
          // Adopt this hop's key BEFORE unsealNode so the outer `finally`
          // zeroes it even if unsealNode throws (leak-on-failure fix). This
          // hop's key supersedes the previous hop's minted key -- zero that
          // now (T-68.1-01-01 pattern); state.folderKey itself is never zeroed.
          mintedReadKey?.fill(0);
          mintedReadKey = childReadKey;

          const childNode = await unsealNode(childResolved.published, childReadKey);

          currentChildren = childNode.children ?? [];
          currentIpnsName = childRef.ipnsName;
          currentSequenceNumber = childResolved.sequenceNumber;
          currentReadKey = childReadKey;
        }

        return await this.resolveListingChildren(
          currentChildren,
          currentReadKey,
          currentIpnsName,
          currentSequenceNumber
        );
      } finally {
        mintedReadKey?.fill(0);
      }
    });
  }

  /**
   * Download and decrypt a shared file's content by walking the full
   * grant->leaf read-chain (D-07 full-boundary facade, 68.2-08 Rule-2
   * addition -- not in this plan's original `<files_modified>`, added
   * because no existing facade covered shared single-file download).
   *
   * Wraps `sdkCore.navigateReadChain` (UNCHANGED -- per 68.2-RESEARCH.md's
   * explicit guidance, this primitive is not modified because it has other
   * existing callers) plus the fetch+decrypt orchestration that previously
   * lived directly in `apps/web/src/hooks/useSharedNavigationActions.ts`'s
   * `downloadSharedFile`/`loadSharedFileContent`. This method only MOVES
   * that orchestration into the SDK so the web stops importing
   * `navigateReadChain`/`fetchFromIpfs` (sdk-core) at runtime for shared
   * file reads.
   *
   * `path` is the sequence of ipnsNames strictly between the share root and
   * the leaf, INCLUSIVE of the leaf -- empty when the share root IS the file
   * (single-file share) or when the file is a direct child of the currently
   * viewed folder depth.
   *
   * @param args.encryptedReadKey - HEX-encoded ECIES-wrapped share-root
   *   readKey (the `ReceivedShare`/API DTO wire contract) -- bridged to
   *   `navigateReadChain`'s base64 contract internally.
   * @param args.recipientPrivateKey - Caller-owned, NEVER zeroed here (D-09).
   * @security The minted share-root/intermediate readKeys and the leaf's raw
   *   fileKey are recovered and zeroed entirely inside `navigateReadChain`
   *   and this method -- only decrypted plaintext leaves this method.
   */
  async downloadSharedFile(args: {
    encryptedReadKey: string;
    recipientPrivateKey: Uint8Array;
    shareRootIpnsName: string;
    rootExpectedGeneration: number;
    path: string[];
  }): Promise<
    | { status: 'revoked' }
    | { status: 'behind-retry' }
    | { status: 'ok'; plaintext: Uint8Array; mimeType: string; encryptionMode: EncryptionMode }
  > {
    return this.withOperation('downloadSharedFile', async () => {
      const result = await sdkCore.navigateReadChain({
        encryptedReadKey: sharedFileBytesToBase64(hexToBytes(args.encryptedReadKey)),
        recipientPrivKey: args.recipientPrivateKey,
        shareRootIpnsName: args.shareRootIpnsName,
        rootExpectedGeneration: args.rootExpectedGeneration,
        path: args.path,
        ctx: this.ctx,
      });

      if (result.status === 'revoked') return { status: 'revoked' as const };
      if (result.status === 'behind-retry') return { status: 'behind-retry' as const };

      const { content } = result;
      try {
        const ciphertext = await sdkCore.fetchFromIpfs(this.ctx, content.cid);
        const iv = sharedFileBase64ToBytes(content.fileIv);
        const plaintext =
          content.encryptionMode === 'CTR'
            ? await decryptAesCtr(ciphertext, content.fileKey, iv)
            : await decryptAesGcm(ciphertext, content.fileKey, iv);
        return {
          status: 'ok' as const,
          plaintext,
          mimeType: content.mimeType,
          encryptionMode: content.encryptionMode,
        };
      } finally {
        // Terminal owner of the raw fileKey recovered inside NodeContent (D-09).
        content.fileKey.fill(0);
      }
    });
  }

  /**
   * Resolve a share's ROOT node from its grant encrypted key (D-07 full-boundary
   * facade, 68.2-08 Rule-2 addition -- the share-ENTRY counterpart to
   * {@link resolveChildIdentity}'s per-child descent). ONE ECIES unwrap of
   * `encryptedReadKey` -> shareRootReadKey, resolve+unseal the root Node.
   * Hoisted verbatim from `useSharedNavigationActions.ts`'s `navigateToShare`
   * (the raw-crypto portion only -- UI state wiring/seeding stays in the web
   * hook).
   *
   * @security `recipientPrivateKey` is caller-owned, NEVER zeroed here
   *   (D-09). On `'ok'`, the caller becomes the terminal owner of the
   *   returned `readKey` (must zero it once superseded/discarded/consumed).
   */
  async resolveShareRoot(args: {
    encryptedReadKey: string;
    recipientPrivateKey: Uint8Array;
    shareRootIpnsName: string;
    rootExpectedGeneration?: number;
  }): Promise<
    | { status: 'revoked' }
    | { status: 'behind-retry' }
    | {
        status: 'ok';
        kind: NodeKind;
        readKey: Uint8Array;
        children: SealedChildRef[];
        sequenceNumber: bigint;
        published: PublishedNode;
      }
  > {
    return this.withOperation('resolveShareRoot', async () => {
      const shareRootReadKey = await unwrapKey(
        hexToBytes(args.encryptedReadKey),
        args.recipientPrivateKey
      );
      let committed = false;
      try {
        const resolved = await this.resolvePublishedNode(args.shareRootIpnsName);
        if (!resolved) return { status: 'revoked' as const };
        if (
          args.rootExpectedGeneration !== undefined &&
          resolved.published.generation > args.rootExpectedGeneration
        ) {
          return { status: 'behind-retry' as const };
        }
        const rootNode = await unsealNode(resolved.published, shareRootReadKey);
        committed = true;
        return {
          status: 'ok' as const,
          kind: rootNode.kind,
          readKey: shareRootReadKey,
          children: rootNode.children ?? [],
          sequenceNumber: resolved.sequenceNumber,
          published: resolved.published,
        };
      } finally {
        if (!committed) shareRootReadKey.fill(0);
      }
    });
  }

  /**
   * Descend one hop into a shared CHILD folder (D-07 full-boundary facade,
   * 68.2-08 Rule-2 addition) -- gated-resolve the child, unseal its readKey
   * under the CURRENT depth's readKey (generation-source rule:
   * `childRef.generation`, the parent mirror, never the child's own envelope
   * generation), then unseal the child Node to recover its OWN children +
   * sequence. Mirrors {@link listSharedFolder}'s internal per-hop loop body,
   * but returns the RAW `SealedChildRef[]` (the web still needs these for
   * nav-stack/write-op identity, e.g. `updateSharedFile`'s
   * `readKeySealed`-dependent filePointer) instead of the resolved display
   * projection -- callers needing `ResolvedChild[]` for THIS depth should
   * call {@link listSharedFolder} separately (cached, cheap).
   *
   * @returns `null` when the child's IPNS record is no longer resolvable
   *   (revoked/not-found) -- fail-closed, matches `gatedResolveChild`.
   * @security Never zeros `parentReadKey` (caller-owned, D-09). The caller
   *   becomes the terminal owner of the returned `readKey`.
   */
  async descendSharedChild(
    childRef: SealedChildRef,
    parentReadKey: Uint8Array
  ): Promise<{
    readKey: Uint8Array;
    children: SealedChildRef[];
    sequenceNumber: bigint;
    published: PublishedNode;
  } | null> {
    return this.withOperation('descendSharedChild', async () => {
      const resolved = await this.gatedResolveChild(childRef);
      if (!resolved) return null;
      const readKey = await unsealChildReadKey(
        childRef.readKeySealed,
        parentReadKey,
        resolved.published.id,
        resolved.published.kind,
        childRef.generation // parent mirror -- NEVER resolved.published.generation
      );
      let committed = false;
      try {
        const node = await unsealNode(resolved.published, readKey);
        committed = true;
        return {
          readKey,
          children: node.children ?? [],
          sequenceNumber: resolved.sequenceNumber,
          published: resolved.published,
        };
      } finally {
        if (!committed) readKey.fill(0);
      }
    });
  }

  /**
   * Resolve a node's plaintext identity (id + kind) from its IPNS name,
   * without requiring any readKey -- `id`/`kind` are PLAINTEXT on the
   * `PublishedNode` envelope (NODE-03), so no decryption is needed (D-07
   * full-boundary facade, 68.2-08 Rule-2 addition -- replaces
   * `useSharedWriteOps.ts`'s direct `resolveIpnsRecord`+`fetchFromIpfs`
   * usage for `deleteFromSharedFolder`'s `childNodeId` resolution).
   *
   * @returns `null` when the IPNS record cannot be resolved (revoked/not found).
   */
  async resolveNodeIdentity(ipnsName: string): Promise<{ nodeId: string; kind: NodeKind } | null> {
    return this.withOperation('resolveNodeIdentity', async () => {
      const resolved = await this.resolvePublishedNode(ipnsName);
      if (!resolved) return null;
      return { nodeId: resolved.published.id, kind: resolved.published.kind };
    });
  }

  /**
   * Resolve the write-body params (`writeKey` + current `writeChildren`) an owned
   * publish call site must thread into `updateFolderMetadataAndPublish` so the
   * republished folder PRESERVES its existing write chain (D-03).
   *
   * This plan only preserves existing writeChildren on republish — it never
   * adds/removes WriteChildRef entries (insertion is owned by createFolder
   * 68.1-02 and the owned-file-write plans 68.1-07/09).
   *
   * Sourcing order:
   *   1. Legacy zero-fallback writeKey (registerFolder/loadFolder without a real
   *      key) → return `{}` so the publish stays write-body-less, identical to
   *      pre-D-03 behavior. Sealing under a zero key is exactly the
   *      T-68.1-01-03 threat this avoids.
   *   2. In-memory `folder.metadata.writeBody` (populated by ensureFolderLoaded,
   *      which unseals with the real writeKey) → use its writeChildren directly.
   *   3. Otherwise unseal the CURRENT on-wire node once per operation
   *      (shared-write pattern: unsealNode with readKey+writeKey →
   *      writeBody.writeChildren). An absent on-wire write-body (pre-D-03
   *      publish) yields `[]` — the republish then seals a fresh empty
   *      write-body going forward. A write-body that IS present but fails GCM
   *      auth under folder.writeKey propagates as a throw (fail-closed,
   *      T-68.1-01-03) rather than silently dropping entries.
   *
   * Never zeroes folder.folderKey / folder.writeKey (caller-owned, D-09).
   */
  private async getWriteBodyParams(
    folder: FolderState
  ): Promise<{ writeKey?: Uint8Array; writeChildren?: WriteChildRef[] }> {
    const wk = folder.writeKey;
    if (!wk || wk.length !== 32 || wk.every((b) => b === 0)) {
      return {};
    }
    if (folder.metadata?.writeBody) {
      return { writeKey: wk, writeChildren: folder.metadata.writeBody.writeChildren };
    }
    const resolved = await this.resolvePublishedNode(folder.ipnsName);
    if (!resolved) {
      // 72-04 SC#2: a real writeKey is present but the resolve genuinely
      // came back null (transient IPNS resolve miss) — fail CLOSED rather
      // than returning writeChildren: [], which would let the next publish
      // seal an EMPTY write-body and silently discard the entire write
      // chain. Distinct from the `!writeSealed` case below (a structurally
      // never-write-capable folder), which stays fail-open (Pitfall 3 / A1).
      throw new Error(
        `getWriteBodyParams: transient IPNS resolve miss for folder ${folder.ipnsName}; refusing to seal an empty write-body and discard the write chain`
      );
    }
    if (!resolved.published.writeSealed) {
      // Resolved fine, but no write-body was ever sealed — start with [].
      return { writeKey: wk, writeChildren: [] };
    }
    const node = await unsealNode(resolved.published, folder.folderKey, wk);
    return { writeKey: wk, writeChildren: node.writeBody?.writeChildren ?? [] };
  }

  /**
   * Adopt a successful `updateFolderMetadataAndPublish` result into the
   * in-memory FolderState, INCLUDING the unsealed `metadata` Node mirror when
   * present (68.1-22).
   *
   * `getWriteBodyParams` prefers `metadata.writeBody.writeChildren` and
   * `dfsFindFolder` walks `metadata.writeBody` directly, so leaving the mirror
   * stale after a publish makes the NEXT mutation re-seal an OUTDATED write
   * chain — silently dropping WriteChildRefs inserted by earlier mutations in
   * the same session. That drop is what made cold-reload DFS descent unable to
   * recover just-created subfolders (GAP-2 symptom) and made
   * resolveShareEncryptedWriteKey fail closed on freshly-created items.
   */
  private adoptPublishedFolderState(
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
          // 68.1-29: the folder carried a read-only metadata mirror (no
          // write-body — e.g. loaded via loadFolder, or getWriteBodyParams
          // sourced the chain from the on-wire node rather than the mirror) but
          // this publish sealed a real write chain. CREATE the mirror so the
          // next getWriteBodyParams (prefers metadata.writeBody) and DFS descent
          // (walks metadata.writeBody.writeChildren) see the new WriteChildRefs
          // instead of the absent-mirror fallback that dropped them.
          folder.metadata.writeBody = {
            ipnsPrivateKey: new Uint8Array(folder.ipnsKeypair.privateKey),
            writeChildren: publishedWriteChildren,
          };
        }
      }
    }
    this.folderTree.set(folder.ipnsName, folder);
  }

  /**
   * Seed (or return the cached) root FolderState from config, unsealing the root
   * Node's write-body so DFS descent has the root's writeChildren available (D-03).
   *
   * Returns null when self-bootstrap is unavailable (no rootIpnsKeypair or
   * rootWriteKey configured — Phase 68.1-03 wires these at the host layer) or the
   * root IPNS record itself cannot be resolved (structurally unresolvable hop).
   */
  private async ensureRootFolderState(): Promise<FolderState | null> {
    const existingRoot = this.folderTree.get(this.config.rootIpnsName);
    if (existingRoot) return existingRoot;

    if (!this.internalRootIpnsKeypair || !this.internalRootWriteKey) return null;

    const resolvedRoot = await this.resolvePublishedNode(this.config.rootIpnsName);
    if (!resolvedRoot) return null;

    // 68.2-01: gate the root resolve through the durable ROT-07 floor. The
    // root has no parent SealedChildRef mirror to source `generation` from
    // (unlike a child hop in dfsFindFolder below), so this mirrors the
    // write-path gate (reconcileFolderSequence) and sources `generation`
    // from the in-memory folderTree entry (absent on first contact — 0).
    // `versionFloor` is 0: the root is the client's own self-bootstrapped
    // node, not a covering grant from another party, so there is no
    // owner-vouched cold-device floor to apply beyond "non-negative".
    if (this.config.rotationHighWater) {
      if (!resolvedRoot.signatureVerified) {
        throw new Error(
          `IPNS resolve for ${this.config.rootIpnsName} returned an unverified record -- refusing to gate durable floors on it`
        );
      }
      if (resolvedRoot.sequenceNumber > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(
          `IPNS sequence number for ${this.config.rootIpnsName} exceeds Number.MAX_SAFE_INTEGER -- refusing lossy floor conversion`
        );
      }
      const nodeGeneration = this.folderTree.get(this.config.rootIpnsName)?.nodeGeneration ?? 0;
      await this.config.rotationHighWater.enforceResolved({
        nodeId: this.config.rootIpnsName,
        seq: Number(resolvedRoot.sequenceNumber),
        generation: nodeGeneration,
        versionFloor: 0,
      });
    }

    // Fail closed on a wrong/corrupted root key — a genuine crypto/config error,
    // not a structurally-unresolvable hop, so this is intentionally NOT caught.
    const rootNode = await unsealNode(
      resolvedRoot.published,
      this.internalRootFolderKey,
      this.internalRootWriteKey
    );

    const rootState: FolderState = {
      ipnsName: this.config.rootIpnsName,
      folderKey: new Uint8Array(this.internalRootFolderKey),
      writeKey: new Uint8Array(this.internalRootWriteKey),
      ipnsKeypair: {
        publicKey: new Uint8Array(this.internalRootIpnsKeypair.publicKey),
        privateKey: new Uint8Array(this.internalRootIpnsKeypair.privateKey),
      },
      sequenceNumber: resolvedRoot.sequenceNumber,
      children: rootNode.children ?? [],
      metadata: rootNode,
      lastLoadedAt: Date.now(),
      nodeId: rootNode.id,
      nodeGeneration: rootNode.generation,
    };
    this.folderTree.set(this.config.rootIpnsName, rootState);
    return rootState;
  }

  /**
   * DFS descent from `parentState` searching for `targetIpnsName`, recovering
   * each visited folder's readKey + writeKey + ipnsPrivateKey from the write
   * chain and registering it into folderTree along the way (early-exit once
   * the target is found).
   *
   * Per-hop crypto derivation follows the generation-source rule (§2.6, matching
   * navigateReadChain): `childRef.generation` (the PARENT MIRROR) is the AAD
   * input for both unsealChildReadKey and unsealChildWriteKey — NEVER the
   * child's own envelope generation. A stale-CID relay serve fails GCM auth
   * closed (T-68.1-01-02) and propagates as a throw, matching navigateReadChain's
   * documented "AEAD auth failure propagates as a throw, not silent success"
   * contract. Only structurally-absent hops (missing IPNS record, missing write
   * link) are soft failures that skip to the next sibling.
   *
   * Cache short-circuit (68.1-26): a child already present in `folderTree`
   * WITH a real (non-zero) writeKey is reused as-is instead of being
   * re-resolved/re-unsealed/re-overwritten. Prior behavior always re-walked
   * EVERY intermediate ancestor on EVERY call (even once fully cached), so
   * navigating into a second, deeper subfolder redid a full network
   * resolve+unseal for every already-loaded ancestor along the path and
   * clobbered its `folderTree` entry with the fresh (but redundant) result —
   * contradicting this method's own "later calls are cheap" contract and
   * exposing loaded ancestors to being overwritten by later, possibly
   * transiently-inconsistent resolves during an unrelated deeper descent. A
   * write-capable cached entry is exactly as authoritative here as it is at
   * the `ensureFolderLoaded` top-level cache-hit branch, which already
   * trusts it without a re-resolve. A read-only-seeded cached entry (zero
   * writeKey — e.g. the web-layer's parallel `navigateReadChain` walk,
   * 68.1-05) is intentionally NOT short-circuited: it still needs the full
   * write-chain recovery below so a write-capable root can recover its real
   * writeKey (matching `recoverWriteKeyIfNeeded`'s 68.1-23 guarantee).
   *
   * `visited` guards against a cyclic/malicious tree hanging the walk.
   */
  private async dfsFindFolder(
    parentState: FolderState,
    targetIpnsName: string,
    visited: Set<string>
  ): Promise<FolderState | null> {
    if (visited.has(parentState.ipnsName)) return null;
    visited.add(parentState.ipnsName);

    const parentNode = parentState.metadata;
    if (!parentNode) return null;

    for (const childRef of parentNode.children ?? []) {
      const cachedChild = this.folderTree.get(childRef.ipnsName);
      const cachedWriteKey = cachedChild?.writeKey;
      const cachedHasRealWriteKey =
        !!cachedWriteKey && cachedWriteKey.length === 32 && !cachedWriteKey.every((b) => b === 0);
      if (cachedChild && cachedHasRealWriteKey) {
        if (childRef.ipnsName === targetIpnsName) return cachedChild;
        // Only DESCEND THROUGH a cached child that is actually traversable — i.e.
        // has an unsealed write-body mirror. A registerFolder-seeded entry
        // (68.1-02 createFolder registers the new child with a real writeKey but
        // metadata:null) has a real writeKey yet cannot be descended: recursing
        // hits `if (!parentNode) return null` at the top of this method and, with
        // the `continue` below, would wrongly SKIP the whole subtree — blocking
        // network recovery of an uncached deeper target. Fall through to the
        // network resolve/unseal path, which rebuilds the full traversable state.
        if (cachedChild.metadata?.writeBody) {
          const foundCached = await this.dfsFindFolder(cachedChild, targetIpnsName, visited);
          if (foundCached) return foundCached;
          continue;
        }
      }

      const childResolved = await this.resolvePublishedNode(childRef.ipnsName);
      if (!childResolved) continue; // structurally unresolvable hop — try siblings

      let childReadKey: Uint8Array | null = null;
      let childWriteKey: Uint8Array | null = null;
      try {
        // 68.2-01 (ROT-07, SDK-READ-01): gate this read-path resolve through
        // the durable anti-rollback floor BEFORE the resolve is trusted for
        // any unseal below. Fail closed on an unverified record BEFORE any
        // floor mutation (T-68.2-02) -- a relay could otherwise forge a huge
        // seq/generation and permanently wedge this node behind a regression
        // error. Generation-source rule (Pitfall 3 / T-68.2-03): sources
        // `generation` from childRef.generation (the PARENT SealedChildRef
        // mirror), NEVER childResolved.published.generation (the child's own
        // envelope generation) -- matching the unsealChildReadKey call below.
        if (this.config.rotationHighWater) {
          if (!childResolved.signatureVerified) {
            throw new Error(
              `IPNS resolve for ${childRef.ipnsName} returned an unverified record -- refusing to gate durable floors on it`
            );
          }
          if (
            childResolved.sequenceNumber > BigInt(Number.MAX_SAFE_INTEGER) ||
            childRef.versionFloor > BigInt(Number.MAX_SAFE_INTEGER)
          ) {
            throw new Error(
              `IPNS sequence number for ${childRef.ipnsName} exceeds Number.MAX_SAFE_INTEGER -- refusing lossy floor conversion`
            );
          }
          await this.config.rotationHighWater.enforceResolved({
            nodeId: childRef.ipnsName,
            seq: Number(childResolved.sequenceNumber),
            generation: childRef.generation,
            versionFloor: Number(childRef.versionFloor),
          });
        }

        // Generation-source rule: childRef.generation (parent mirror), NEVER
        // childResolved.published.generation (child's own envelope generation).
        childReadKey = await unsealChildReadKey(
          childRef.readKeySealed,
          parentState.folderKey,
          childResolved.published.id,
          childResolved.published.kind,
          childRef.generation
        );

        // Only folder/root kinds can carry a write-body and be descended into
        // further — a file leaf is never a FolderState target.
        if (childResolved.published.kind !== 'folder' && childResolved.published.kind !== 'root') {
          continue;
        }

        const writeChildRef = parentNode.writeBody?.writeChildren.find(
          (wc) => wc.childId === childResolved.published.id
        );
        if (!writeChildRef) {
          // No write link recorded for this child (e.g. pre-D-03 folder never
          // republished with a write-body) — not self-writable, skip.
          continue;
        }
        childWriteKey = await unsealChildWriteKey(
          writeChildRef.writeKeySealed,
          parentState.writeKey,
          childResolved.published.id,
          childResolved.published.kind,
          childRef.generation
        );

        // T-68.1-01-03: unsealNode validates the recovered writeKey (throws on
        // wrong key) BEFORE the recovered ipnsPrivateKey is ever trusted —
        // intentionally not caught here (fail closed).
        const childNode = await unsealNode(childResolved.published, childReadKey, childWriteKey);
        if (!childNode.writeBody) continue;

        const childState: FolderState = {
          ipnsName: childRef.ipnsName,
          folderKey: new Uint8Array(childReadKey),
          writeKey: new Uint8Array(childWriteKey),
          ipnsKeypair: {
            publicKey: deriveEd25519PublicKey(childNode.writeBody.ipnsPrivateKey),
            privateKey: new Uint8Array(childNode.writeBody.ipnsPrivateKey),
          },
          sequenceNumber: childResolved.sequenceNumber,
          children: childNode.children ?? [],
          metadata: childNode,
          lastLoadedAt: Date.now(),
          nodeId: childNode.id,
          nodeGeneration: childNode.generation,
        };
        // folderTree.set() makes its own defensive copy (D-09), so the local
        // childReadKey/childWriteKey buffers below are always safe to zero.
        this.folderTree.set(childRef.ipnsName, childState);

        if (childRef.ipnsName === targetIpnsName) return childState;

        const found = await this.dfsFindFolder(childState, targetIpnsName, visited);
        if (found) return found;
      } finally {
        // T-68.1-01-01: zero navigate-minted intermediates not retained beyond
        // this local scope. NEVER zero parentState.folderKey/writeKey (D-09 —
        // caller/folderTree-owned) or config root keys.
        childReadKey?.fill(0);
        childWriteKey?.fill(0);
      }
    }

    return null;
  }

  /**
   * Ensure a folder is present in the internal folderTree, self-bootstrapping
   * from root if necessary.
   *
   * If the target is already loaded, returns it immediately. Otherwise — when a
   * root IPNS keypair AND root write key were configured — walks the folder tree
   * from root (DFS with early exit), resolving each folder's Node and recovering
   * each subfolder's readKey + writeKey + ipnsPrivateKey from the write chain
   * (SealedChildRef.readKeySealed + WriteChildRef.writeKeySealed — D-03; the
   * legacy `folderKeyEncrypted`/`ipnsPrivateKeyEncrypted` fields no longer exist
   * on SealedChildRef, NODE-03), until the target is registered. Every folder
   * visited along the way is cached, so later calls are cheap.
   *
   * Returns null when the client cannot self-bootstrap (no `rootIpnsKeypair` or
   * `rootWriteKey` configured, or the root IPNS record itself is unresolvable)
   * or the target is not reachable from root. Callers fall back to their
   * existing 'Folder not loaded' error on null, so behavior is unchanged when
   * self-bootstrap is unavailable. This dissolves the "Folder not loaded"
   * failure class that previously required consumers to pre-seed folderTree
   * before every folderTree-dependent operation.
   *
   * `opts.forceResolve` (68.2-13, SDK-READ-03 / SC#5) is a DELIBERATE,
   * distinct live-resolve-on-navigation path: for an ALREADY-LOADED entry,
   * it routes to {@link reresolveFolderInPlace} instead of this method's
   * verbatim short-circuit -- gated re-resolving the folder's OWN IPNS
   * record from the network and advancing the stored `FolderState` in
   * place, closing the self-referential cache-clock gap where a repeat
   * `ensureFolderLoaded`/`listFolder` call for an already-loaded folder
   * never saw a grantee's later write. Internal write-mutation chokepoints
   * (`requireFolder`, etc.) call this method with NO opts and keep the
   * cheap cached fast path untouched.
   *
   * @param targetIpnsName - IPNS name of the folder to ensure is loaded
   * @returns The loaded FolderState, or null if it cannot be bootstrapped
   * @internal
   */
  async ensureFolderLoaded(
    targetIpnsName: string,
    opts?: { forceResolve?: boolean }
  ): Promise<FolderState | null> {
    const existing = this.folderTree.get(targetIpnsName);
    if (existing) {
      if (opts?.forceResolve) {
        return this.reresolveFolderInPlace(existing);
      }
      // Cold-load write-plane recovery (68.1-23): a folder entry seeded
      // read-only (registerFolder/loadFolder without a writeKey -- e.g. the
      // web-layer's parallel navigateReadChain walk, 68.1-05) pre-empts the
      // DFS recovery below since we short-circuit here. Recover the real
      // writeKey + populated write-body mirror for THIS folder when possible.
      await this.recoverWriteKeyIfNeeded(existing);
      return existing;
    }

    const rootState = await this.ensureRootFolderState();
    if (!rootState) return null;
    if (targetIpnsName === this.config.rootIpnsName) return rootState;

    return this.dfsFindFolder(rootState, targetIpnsName, new Set<string>());
  }

  /**
   * Dedup wrapper (T-68.2-13-04) around {@link doReresolveFolderInPlace}:
   * coalesces concurrent `{ forceResolve: true }` calls for the SAME
   * `ipnsName` (e.g. a nav re-resolve and the 30s poll leg firing together)
   * to a single network resolve, sharing one in-flight promise.
   */
  private reresolveFolderInPlace(existing: FolderState): Promise<FolderState | null> {
    const ipnsName = existing.ipnsName;
    const inFlight = this.reresolveInFlight.get(ipnsName);
    if (inFlight) return inFlight;

    const promise = this.doReresolveFolderInPlace(existing).finally(() => {
      this.reresolveInFlight.delete(ipnsName);
    });
    this.reresolveInFlight.set(ipnsName, promise);
    return promise;
  }

  /**
   * Gated live-resolve-on-navigation for an ALREADY-LOADED folder (68.2-13,
   * SDK-READ-03 / SC#5). Re-resolves the folder's OWN IPNS record from the
   * network and, when genuinely newer, updates the EXISTING `FolderState`
   * object in place (D-09 single-owner, SC#3 -- never a second state object
   * or a second store).
   *
   * GATED re-resolve (D-05): mirrors `dfsFindFolder`'s per-hop gate block
   * exactly -- fail closed on `!signatureVerified` BEFORE any floor
   * mutation, guard `Number.MAX_SAFE_INTEGER` overflow, then gate through
   * `RotationHighWater.enforceResolved`. `generation` is sourced from
   * `existing.nodeGeneration` (a locally-trusted, previously-gate-validated
   * value) -- NEVER the freshly relay-served envelope generation (Pitfall
   * 3). `versionFloor: 0` mirrors `ensureRootFolderState`'s own gate: the
   * seqFloor is already established for an already-loaded node, so it is
   * never consulted. Gate errors and AEAD unseal errors PROPAGATE
   * (fail-closed, matching `dfsFindFolder`'s T-68.1-01-02 contract) --
   * fire-and-forget web freshness callers swallow them.
   *
   * A null resolve (structurally unresolvable / transient network miss) or
   * a resolved sequence that is not strictly newer (#489 sequence-as-clock
   * guard, mirrors `loadFolder`'s own guard) returns `existing` unchanged
   * without re-unsealing -- never blows away a loaded view on a stale or
   * failed read.
   */
  private async doReresolveFolderInPlace(existing: FolderState): Promise<FolderState | null> {
    const resolved = await this.resolvePublishedNode(existing.ipnsName);
    if (!resolved) return existing;

    if (this.config.rotationHighWater) {
      if (!resolved.signatureVerified) {
        throw new Error(
          `IPNS resolve for ${existing.ipnsName} returned an unverified record -- refusing to gate durable floors on it`
        );
      }
      if (resolved.sequenceNumber > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(
          `IPNS sequence number for ${existing.ipnsName} exceeds Number.MAX_SAFE_INTEGER -- refusing lossy floor conversion`
        );
      }
      await this.config.rotationHighWater.enforceResolved({
        nodeId: existing.ipnsName,
        seq: Number(resolved.sequenceNumber),
        generation: existing.nodeGeneration,
        versionFloor: 0,
      });
    }

    // Sequence-as-clock guard (#489): the gate above has already rejected
    // any true regression; an equal/stale-lagging read is not fresher than
    // what's already stored, so return existing unchanged without
    // re-unsealing (mirrors loadFolder's own guard).
    if (resolved.sequenceNumber <= existing.sequenceNumber) {
      return existing;
    }

    const wk = existing.writeKey;
    const hasRealWriteKey = !!wk && wk.length === 32 && !wk.every((b) => b === 0);
    const node = hasRealWriteKey
      ? await unsealNode(resolved.published, existing.folderKey, existing.writeKey)
      : await unsealNode(resolved.published, existing.folderKey);

    // In-place update (D-09 single-owner, SC#3): preserve writeKey/
    // ipnsKeypair/nodeId, advance the cache clock + write-plane mirror.
    existing.sequenceNumber = resolved.sequenceNumber;
    existing.children = node.children ?? [];
    existing.metadata = node;
    existing.nodeGeneration = node.generation;
    existing.lastLoadedAt = Date.now();
    this.folderTree.set(existing.ipnsName, existing);

    await this.recoverWriteKeyIfNeeded(existing);

    return existing;
  }

  /**
   * Recover a real writeKey + populated `metadata.writeBody` for a folder
   * entry that was seeded read-only (zero writeKey, e.g. via
   * `registerFolder`/`loadFolder` without a `writeKey` argument) but IS
   * reachable from a write-capable root (68.1-23 gap-closure).
   *
   * No-op when: the entry already carries a real writeKey; no root write
   * material is configured (`internalRootIpnsKeypair`/`internalRootWriteKey`
   * absent -- read-only clients stay read-only, unchanged behavior); the
   * entry IS the root (`ensureRootFolderState` always seeds a real writeKey);
   * or the folder is not reachable from root (DFS returns null).
   *
   * Adopts ONLY the write-plane fields (`writeKey`, `metadata.writeBody`) onto
   * the pre-existing `FolderState` object -- its readKey/ipnsKeypair/
   * sequenceNumber/children stay exactly as already loaded (D-09: never
   * replace a caller/folderTree-owned read-plane view with a network re-walk).
   */
  private async recoverWriteKeyIfNeeded(existing: FolderState): Promise<void> {
    const wk = existing.writeKey;
    const hasRealWriteKey = !!wk && wk.length === 32 && !wk.every((b) => b === 0);
    if (hasRealWriteKey) return;
    if (!this.internalRootIpnsKeypair || !this.internalRootWriteKey) return;
    if (existing.ipnsName === this.config.rootIpnsName) return;

    const rootState = await this.ensureRootFolderState();
    if (!rootState) return;

    const recovered = await this.dfsFindFolder(rootState, existing.ipnsName, new Set<string>());
    if (!recovered) return;

    existing.writeKey = new Uint8Array(recovered.writeKey);
    existing.metadata = existing.metadata
      ? {
          ...existing.metadata,
          writeBody: recovered.metadata?.writeBody ?? existing.metadata.writeBody,
        }
      : recovered.metadata;
    this.folderTree.set(existing.ipnsName, existing);
  }

  /**
   * Resolve a folder from internal state, self-bootstrapping from root if needed.
   *
   * Returns the loaded FolderState or throws `${label} not loaded`. This is the
   * single chokepoint every folderTree-dependent mutation routes through, so the
   * get-or-self-load-or-throw contract lives in one place and a new method can't
   * silently forget the self-heal fallback.
   *
   * Always routes through `ensureFolderLoaded` (rather than short-circuiting on
   * an existing folderTree entry) so the cold-load write-plane recovery
   * (`recoverWriteKeyIfNeeded`, 68.1-23) also fires for already-loaded,
   * read-only-seeded entries.
   *
   * @param ipnsName - IPNS name of the required folder
   * @param label - Human label for the error (e.g. 'Parent folder', 'Source folder')
   */
  private async requireFolder(ipnsName: string, label = 'Folder'): Promise<FolderState> {
    const folder = await this.ensureFolderLoaded(ipnsName);
    if (!folder) throw new Error(`${label} not loaded`);
    return folder;
  }

  /**
   * Reconcile-before-publish guard (SC#3 / D-04).
   *
   * Re-resolves `ipnsName`'s CURRENT network `sequenceNumber` and compares it
   * against `expectedSequence` -- the in-memory `FolderTree` value the caller
   * is about to publish against. ANY mismatch (network ahead OR local ahead)
   * throws {@link ReconcileStaleError} so the caller defers instead of
   * publishing a metadata update or a rotation against possibly-superseded
   * state ("defer, never skip").
   *
   * A null resolve (record not found -- e.g. a genuinely first publish) or a
   * resolve without a usable `sequenceNumber` is treated as "nothing to
   * reconcile against" and the check is skipped. A resolve() failure (network
   * error) is likewise treated as inconclusive rather than blocking the
   * mutation on a transient check -- the underlying CAS-guarded publish
   * remains the authoritative conflict detector.
   *
   * SC#5/D-09: when a `RotationHighWater` is configured, the durable
   * generation gate MUST be fed the record's ACTUAL generation -- fetched
   * from IPFS and unsealed with `folderReadKey` -- not the in-memory
   * `folderTree.get(ipnsName)?.nodeGeneration`, which only reflects the
   * client's OWN last successful load/publish and can equivocate against a
   * self-inflicted lower-generation republish at a higher sequence. The
   * fetch+unseal happens ONLY on this write-path reconcile, never on the 30s
   * poll. A failed unseal (wrong/absent read key, tampered body) fails
   * closed -- it is NEVER treated as "nothing to reconcile against" the way
   * a resolve() miss/failure above is.
   */
  private async reconcileFolderSequence(
    ipnsName: string,
    expectedSequence: bigint,
    folderReadKey: Uint8Array
  ): Promise<void> {
    let resolved: { cid: string; sequenceNumber: bigint; signatureVerified: boolean } | null;
    try {
      resolved = await sdkCore.resolveIpnsRecord(ipnsName, this.ctx);
    } catch {
      return;
    }
    if (resolved == null || typeof resolved.sequenceNumber !== 'bigint') return;

    // Durable ROT-07 anti-rollback gate (Gap 1 / SC#4): when a RotationHighWater
    // is injected, gate the freshly-resolved seq/generation through it BEFORE
    // the ReconcileStaleError equality check below. This call is deliberately
    // OUTSIDE the resolve try/catch above so a SequenceRegressionError /
    // GenerationRegressionError propagates to the mutation caller (and thence
    // to useMutationFailureUx's D-05 classifier) rather than being silenced.
    // Omitted when unconfigured -- zero enforcement, matching prior behavior.
    if (this.config.rotationHighWater) {
      // Fail closed BEFORE any floor mutation, symmetric with the read-path
      // gate in apps/web ipns.service: an unverified record must never bump a
      // durable floor -- a relay could otherwise forge a huge seq and
      // permanently wedge every future mutation on this node behind
      // SequenceRegressionError. Rotation-participating nodes are always
      // published signed, so an unverified record here is itself a red flag.
      if (!resolved.signatureVerified) {
        throw new Error(
          `IPNS resolve for ${ipnsName} returned an unverified record -- refusing to gate durable floors on it`
        );
      }
      // The durable floor stores JS numbers; sequences beyond MAX_SAFE_INTEGER
      // would silently truncate through Number() and corrupt the floor.
      if (
        resolved.sequenceNumber > BigInt(Number.MAX_SAFE_INTEGER) ||
        expectedSequence > BigInt(Number.MAX_SAFE_INTEGER)
      ) {
        throw new Error(
          `IPNS sequence number for ${ipnsName} exceeds Number.MAX_SAFE_INTEGER -- refusing lossy floor conversion`
        );
      }
      // SC#5/D-09: fetch the resolved CID and unseal it with the folder read
      // key to recover the record's ACTUAL generation. `resolveIpnsRecord`
      // returns no generation field -- generation lives inside the sealed
      // read-body, not the plaintext IPNS envelope -- so the cached
      // folderTree value is never a substitute for this. Any failure here
      // (network, malformed envelope, or AEAD/unseal failure under the
      // supplied key) propagates and fails the reconcile closed -- it must
      // NEVER be swallowed into a fallback on the cached generation.
      const rawNode = await sdkCore.fetchFromIpfs(this.ctx, resolved.cid);
      const publishedNode = JSON.parse(new TextDecoder().decode(rawNode)) as PublishedNode;
      const unsealedNode = await unsealNode(publishedNode, folderReadKey);
      await this.config.rotationHighWater.enforceResolved({
        nodeId: ipnsName,
        seq: Number(resolved.sequenceNumber),
        generation: unsealedNode.generation,
        versionFloor: Number(expectedSequence),
      });
    }

    if (resolved.sequenceNumber !== expectedSequence) {
      // D-04 self-heal (68.1-22): when the network is AHEAD (a legitimate
      // concurrent update from another device/session), adopt the fresher
      // network state into folderTree BEFORE deferring, so the caller's
      // bounded retry (useMutationFailureUx's runReconcileRetryLoop) re-reads
      // reconciled state and succeeds — previously nothing advanced the local
      // sequence between retries except the 30s sync poll, so the ~30s retry
      // budget raced it and usually exhausted. Network-BEHIND (stale/replayed
      // record, T-68-101) adopts NOTHING — refreshFolderStateFromNetwork's
      // strictly-newer guard skips it, and that direction is classified
      // fail-closed upstream (D-05); adopting it would be a rollback.
      if (resolved.sequenceNumber > expectedSequence) {
        const folder = this.folderTree.get(ipnsName);
        // Only refresh when the in-memory entry still matches the sequence
        // the caller reconciled against (no concurrent in-process update).
        if (folder && folder.sequenceNumber === expectedSequence) {
          await this.refreshFolderStateFromNetwork(folder);
        }
      }
      throw new ReconcileStaleError(ipnsName, expectedSequence, resolved.sequenceNumber);
    }
  }

  /**
   * Best-effort refresh of a folder's in-memory state (read-body children,
   * sequence AND the unsealed metadata mirror incl. write-body) from the
   * CURRENT network record (68.1-22).
   *
   * Strictly-newer guard: never adopts a record at or below the in-memory
   * sequence (anti-rollback — a stale/replayed record must never rewind
   * local state, T-68-101). Failures are swallowed: callers treat this as an
   * opportunistic reconcile, not a correctness gate — the CAS-guarded publish
   * remains the authoritative conflict detector.
   *
   * Why the mirror matters: getWriteBodyParams prefers
   * `metadata.writeBody.writeChildren`, so a stale mirror makes the next
   * publish re-seal an outdated write chain — silently dropping
   * WriteChildRefs inserted by OTHER devices (the cross-device counterpart of
   * adoptPublishedFolderState's same-session sync).
   */
  private async refreshFolderStateFromNetwork(folder: FolderState): Promise<void> {
    try {
      const resolved = await sdkCore.resolveIpnsRecord(folder.ipnsName, this.ctx);
      if (!resolved || typeof resolved.sequenceNumber !== 'bigint') return;
      if (resolved.sequenceNumber <= folder.sequenceNumber) return;
      const raw = await sdkCore.fetchFromIpfs(this.ctx, resolved.cid);
      const published = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
      const wk = folder.writeKey;
      const realWriteKey = wk && wk.length === 32 && !wk.every((b) => b === 0) ? wk : undefined;
      const node = await unsealNode(published, folder.folderKey, realWriteKey);
      if (realWriteKey === undefined) {
        // Write-body preservation (68.1-23): unsealing WITHOUT a real writeKey
        // yields a write-body-less node. Never let that REPLACE an
        // already-populated local mirror -- a second device's bump must not
        // silently strip this device's recovered WriteChildRefs from the wire
        // (D-03). Read-body children/sequence/nodeId/generation still adopt
        // the fresher network view below; only the write-body is preserved.
        node.writeBody = folder.metadata?.writeBody ?? node.writeBody;
      }
      folder.children = node.children ?? [];
      folder.sequenceNumber = resolved.sequenceNumber;
      folder.metadata = node;
      folder.nodeId = node.id;
      folder.nodeGeneration = node.generation;
      folder.lastLoadedAt = Date.now();
      this.folderTree.set(folder.ipnsName, folder);
      this.emitter.emit({
        type: 'folder:updated',
        folderId: folder.ipnsName,
        ipnsName: folder.ipnsName,
        children: await this.resolveListingChildren(
          folder.children,
          folder.folderKey,
          folder.ipnsName,
          folder.sequenceNumber
        ),
        sequenceNumber: folder.sequenceNumber,
      });
    } catch {
      // Best-effort — the caller's publish path still owns conflict handling.
    }
  }

  /**
   * Scope-exit rotation trigger (SC#2 / SC#4), composed via the sdk-core
   * `maybeRotateOnScopeExit` gate. Builds `CoverageParams` from the injected
   * `rotationCallbacks` seam (defaulting to no-op / zero rotation when the
   * host supplies none) and, when covered, invokes `rotateReadFromNode`
   * exactly once via the injected `deps.rotate`.
   *
   * `ancestorIpnsNames` is leaf-first per `scope.ts`'s contract. This SDK does
   * not currently track a full parent-chain in `FolderTree` (out of this
   * plan's file scope), so callers pass the directly-mutated node's own IPNS
   * name(s) -- the coverage check still correctly detects a grant rooted AT
   * the mutated node itself. Extending to a full multi-level ancestor walk
   * requires `FolderTree` parent tracking, deferred to a later plan.
   *
   * ---
   * Plan 70-07 Task 3 trace (Open Question 2) -- PURE-REVOKE ANCESTOR-MIRROR
   * STALENESS, accepted residual, NOT fixed this phase:
   *
   * All FIVE call sites of this method (`createSubfolder`, `renameItem`,
   * `moveItem` [source only], `deleteItem`, `deleteToBin`) invoke it with
   * `rootNodeIpnsName` equal to the folder that was JUST DIRECTLY MUTATED --
   * never a distinct share root reached transitively. `revokeShare` (a PURE
   * revoke -- the shared node's own position in the tree never moves) does
   * NOT call this method at all: it only soft-deletes the share row via the
   * API (`shareOps.revokeShare`). Rotation of that root's read key is
   * therefore entirely DEFERRED to whichever LATER direct mutation
   * (rename/delete/move-out/create-child-under-it) eventually targets that
   * SAME folder -- there is no eager rotation on revoke.
   *
   * Even once that later mutation DOES trigger rotation on the folder,
   * `rotateReadFromNode` (sdk-core `engine.ts`) never re-seals the rotation
   * ROOT's own real ancestor's `SealedChildRef` mirror: `parentTracking` is
   * seeded keyed by `rootNodeIpnsName` itself (to track updates to the
   * root's OWN children), never for the root's true parent -- no
   * `parentTracking` entry is ever created for a node ABOVE the rotation
   * root. So the root's entry inside ITS OWN PARENT's `children[]` still
   * seals the OLD (pre-rotation) key after rotation completes.
   *
   * Consequence for the RootKeyStaleError top-down re-navigation fallback
   * (Task 2, above): a walk from the vault root down through the ancestor
   * chain succeeds through every hop ABOVE the rotation root (their own
   * keys never changed), but is blocked exactly at the LAST hop --
   * parent-to-rotated-root -- because the parent's stored
   * `SealedChildRef.readKeySealed` for that child still seals the stale key.
   * This is the "one hop earlier" residual Task 2's fallback documents.
   *
   * This is an ACCEPTED residual, per the phase's explicit "no redesign"
   * mandate -- making rotation additionally re-seal its own root's ancestor
   * mirror is a larger structural change (rotation would need to learn its
   * caller's parent-chain context, which it does not track today) and is
   * NOT undertaken in this plan. A follow-up todo candidate, not a phase-70
   * scope item.
   * ---
   */
  private async performScopeExitRotation(params: {
    ancestorIpnsNames: string[];
    rootNodeIpnsName: string;
    rootNodeId: string;
    rootReadKey: Uint8Array;
    rootIpnsPrivateKey: Uint8Array;
    rootIpnsPublicKey: Uint8Array;
  }): Promise<void> {
    const callbacks = this.config.rotationCallbacks ?? NOOP_ROTATION_CALLBACKS;
    const activeGrantRootIpnsNames = await callbacks.getActiveGrantRootIpnsNames();
    const localGrantRecord = callbacks.getLocalGrantRecord(params.rootNodeIpnsName);

    // VERIFICATION Gap 2: capture rotateReadFromNode's return so the folderTree
    // entry can be refreshed after a successful rotation below. Stays undefined
    // when maybeRotateOnScopeExit never invokes deps.rotate (uncovered) OR when
    // rotateReadFromNode itself resolves undefined (resume/skip path).
    let rotationResult: sdkCore.RotateReadResult | undefined;

    await sdkCore.maybeRotateOnScopeExit(
      {
        nodeAncestorIpnsNames: params.ancestorIpnsNames,
        activeGrantRootIpnsNames,
        localGrantRecord,
      },
      {
        rotate: async () => {
          const jobRecord: sdkCore.RotationJobRecord = {
            rootNodeId: params.rootNodeId,
            status: 'pending',
            completedNodeIds: new Set(),
            frontier: [],
            persistCallback: callbacks.persistJob,
          };
          try {
            rotationResult = await sdkCore.rotateReadFromNode({
              rootNodeId: params.rootNodeId,
              rootNodeIpnsName: params.rootNodeIpnsName,
              rootReadKey: params.rootReadKey,
              rootIpnsPrivateKey: params.rootIpnsPrivateKey,
              rootIpnsPublicKey: params.rootIpnsPublicKey,
              jobRecord,
              ctx: this.ctx,
              // Phase 65 write-body-derived per-node IPNS keys: every folder
              // already loaded into folderTree carries its OWN real
              // ipnsKeypair + writeKey (populated by ensureFolderLoaded's
              // write-chain recovery), so this is genuine production key
              // material -- not the Phase-64 test-only fixture the
              // RotationParams doc warns against. Nodes not yet loaded into
              // folderTree simply return undefined here (unchanged fallback
              // behavior for those nodes).
              nodeKeySource: (ipnsName) => {
                const folder = this.folderTree.get(ipnsName);
                if (!folder) return undefined;
                return {
                  publicKey: folder.ipnsKeypair.publicKey,
                  privateKey: folder.ipnsKeypair.privateKey,
                  writeKey: folder.writeKey,
                };
              },
              // SC#4 (Plan 70-06) seam plumbing: no CipherBoxClientConfig seam
              // supplies grant-remint callbacks/inner-grants today (Phase 66
              // is the host-wiring follow-up per RESEARCH) -- threading the
              // fields here (currently always undefined) makes them
              // structurally reachable from the real walk without requiring
              // a new config surface in this plan.
              innerGrants: undefined,
              grantCallbacks: undefined,
              // SC#3 (Plan 70.1-05 / D-01..D-05): the owner's OWN vault
              // keypair wraps/unwraps the ECIES key-checkpoint. keyCheckpoint
              // is the seam Plan 70.1-05 added to RotationClientCallbacks --
              // wired by the host (apps/web) to the Plan-02 combined-store
              // IndexedDB accessors (persistWrappedKey/getWrappedKey/
              // deleteWrappedKey). Absent -> zero seam work (unchanged
              // pre-Plan-70.1-05 behavior), matching the NOOP default.
              ownerPublicKey: this.config.vaultKeypair.publicKey,
              ownerPrivateKey: this.config.vaultKeypair.privateKey,
              keyCheckpointCallbacks: callbacks.keyCheckpoint,
            });
          } catch (err) {
            if (err instanceof sdkCore.DirtyNodeUnrecoverableError) {
              // D-05 fallback (child-level, distinct from RootKeyStaleError
              // below): an already-rotated dirty CHILD node's ECIES
              // key-checkpoint was never persisted (a genuinely lost prior
              // run that crashed before D-03's persist-before-publish
              // completed) or has already been GC'd (D-04) -- there is no
              // cryptographic recovery path for a key never checkpointed.
              // Unlike RootKeyStaleError's full top-down re-navigation from
              // the vault root, this residual is scoped to ONE subtree edge:
              // a full repair would re-derive that SPECIFIC node's parent
              // mirror, not re-navigate the entire tree. The error carries no
              // structured node/parent identifier, so that narrower per-node
              // repair is not attempted here -- surface a clear, actionable
              // error instead of an opaque AEAD/unseal failure, consistent
              // with the RootKeyStaleError residual documented below (Phase
              // 70 Open Question 1/2).
              throw new Error(
                `Rotation for root ${params.rootNodeIpnsName} hit an unrecoverable ` +
                  'dirty child (DirtyNodeUnrecoverableError): its ECIES key ' +
                  'checkpoint was never persisted or has already been ' +
                  'garbage-collected, and there is no cryptographic recovery path. ' +
                  'This is a known residual -- reload the app to re-resolve the ' +
                  'affected subtree from the vault root.',
                { cause: err }
              );
            }
            if (!(err instanceof sdkCore.RootKeyStaleError)) throw err;

            // T-70-14 / Open Question 1: the in-memory rootReadKey is stale --
            // this root was rotated by a lost prior session and there is NO
            // cryptographic key-recovery path from the key alone (Pitfall 4).
            // Fall back to a full top-down folderTree re-navigation from the
            // vault root so the client rediscovers the CURRENT key via the
            // parent chain, rather than letting the mutation fail on an
            // opaque unseal error. The stale folderTree entry is dropped
            // FIRST (FolderTree.delete zeroes it as its own terminal owner)
            // so ensureFolderLoaded cannot short-circuit on the same stale
            // cached copy and is forced through the network re-derivation.
            this.folderTree.delete(params.rootNodeIpnsName);
            let recoveryError: unknown;
            const recovered = await this.ensureFolderLoaded(params.rootNodeIpnsName).catch(
              (e: unknown) => {
                recoveryError = e;
                return null;
              }
            );
            if (!recovered) {
              if (recoveryError) {
                // The top-down re-navigation attempt itself threw (network,
                // auth, unseal, etc.) -- that is a DIFFERENT failure than the
                // "known residual" case below (which is a clean not-found
                // resolve, not a thrown error). Surface the real recovery
                // error as `cause` instead of masking every failure behind
                // the generic stale-key message.
                throw new Error(
                  `Rotation root ${params.rootNodeIpnsName} has a stale local read key ` +
                    '(RootKeyStaleError) and the top-down folderTree re-navigation ' +
                    'recovery attempt itself failed. See `cause` for the underlying ' +
                    'error.',
                  { cause: recoveryError }
                );
              }
              // Open Question 2 residual: rotation never updates its OWN
              // root's ancestor SealedChildRef mirror (see
              // performScopeExitRotation's doc comment above), so a
              // pure-revoke root whose ancestor mirror was never re-sealed
              // blocks this top-down re-nav one hop earlier -- it cannot
              // reach the current key either. Surface a clear, actionable
              // error instead of a generic AEAD/unseal failure.
              throw new Error(
                `Rotation root ${params.rootNodeIpnsName} has a stale local read key ` +
                  '(RootKeyStaleError) and could not be recovered via top-down ' +
                  'folderTree re-navigation from the vault root. This is a known ' +
                  'residual of the unrecoverable crash window (Phase 70 Open ' +
                  'Question 1/2) -- reload the app to re-resolve the folder tree ' +
                  'from the vault root.',
                { cause: err }
              );
            }
            // Recovery succeeded: folderTree now holds the CURRENT
            // key/generation/sequenceNumber for this root. rotationResult
            // stays undefined -- the caller's mutation already published
            // successfully; rotation itself is retried on the NEXT covered
            // scope-exit mutation against the now-current state.
            callbacks.progress?.('rotation-key-stale-recovered');
            return;
          }
          callbacks.progress?.('rotated');
        },
      }
    );

    // VERIFICATION Gap 2 (T-68-12-01/03): refresh the in-memory folderTree entry
    // with the ROOT's rotated readKey/generation/sequenceNumber so the next
    // same-session mutation on this folder reconciles cleanly instead of
    // permanently deferring (ReconcileStaleError) until a full page reload.
    // Skipped entirely when rotationResult is undefined (uncovered / resume) --
    // no spurious folderTree write in that case.
    if (rotationResult) {
      const existing = this.folderTree.get(params.rootNodeIpnsName);
      if (existing) {
        // T-68-12-02 / D-09: folderTree is the terminal owner of its OLD
        // folderKey copy -- capture it to zero AFTER the swap below. Never zero
        // rotationResult.readKey (now owned via the defensive copy) nor
        // params.rootReadKey (caller-owned; rotateReadFromNode has already
        // returned, so this is safe post-flight, not mid-flight).
        const oldFolderKey = existing.folderKey;
        this.folderTree.set(params.rootNodeIpnsName, {
          ...existing,
          folderKey: new Uint8Array(rotationResult.readKey),
          sequenceNumber: rotationResult.sequenceNumber,
          nodeGeneration: rotationResult.generation,
          lastLoadedAt: Date.now(),
        });
        oldFolderKey.fill(0);
      }

      // T-70-13 / SC#6: performScopeExitRotation is the TERMINAL OWNER of
      // rotationResult.readKey. rotateReadFromNode always hands over a FRESH
      // COPY on every return path -- including the dirty-resume-republish
      // branch (plan 70-06) -- never an alias of params.rootReadKey, so
      // zeroing it here can never corrupt a live caller-owned buffer. The
      // folderTree entry above already took its OWN independent defensive
      // copy (`new Uint8Array(rotationResult.readKey)`), so this fill(0)
      // touches neither that copy nor params.rootReadKey (see the comment
      // above -- both are distinct buffers from rotationResult.readKey).
      rotationResult.readKey.fill(0);
    }
  }

  /**
   * Best-effort, non-blocking BFS enumeration of a moved folder's descendants
   * (D-12), distinguishing readable descendants (child readKey successfully
   * recovered) from unreadable ones (unseal failed -- key mismatch,
   * generation drift, or a corrupted seal). A moved FILE has no descendants
   * and is a no-op. Failures on a single node do not abort the walk: an
   * unreadable node is recorded and NOT expanded further (its own children
   * cannot be discovered without its key).
   *
   * This is read-only observability -- it does not re-key or mutate
   * anything. It exists so a move does not silently drop or mis-rotate
   * descendants it cannot read; the actual re-rotation of an unreadable
   * subtree remains the rotation engine's job, not this helper.
   *
   * `rootReadKey` MUST be a copy the caller does not otherwise mutate --
   * this method zeroes every key it itself derives while walking (D-09
   * terminal-owner rule for its own minted keys), but never zeroes
   * `rootReadKey` (caller-owned).
   */
  private async enumerateMoveDescendants(
    rootIpnsName: string,
    rootReadKey: Uint8Array,
    rootKind: PublishedNode['kind']
  ): Promise<{ readableIpnsNames: string[]; unreadableIpnsNames: string[] }> {
    const readableIpnsNames: string[] = [];
    const unreadableIpnsNames: string[] = [];

    if (rootKind !== 'folder' && rootKind !== 'root') {
      return { readableIpnsNames, unreadableIpnsNames };
    }

    const visited = new Set<string>([rootIpnsName]);
    const queue: Array<{ ipnsName: string; readKey: Uint8Array; isRoot: boolean }> = [
      { ipnsName: rootIpnsName, readKey: rootReadKey, isRoot: true },
    ];
    // Bound the walk so a pathological/corrupted tree can't hang the move.
    const MAX_NODES = 2000;
    let processed = 0;

    while (queue.length > 0 && processed < MAX_NODES) {
      const current = queue.shift();
      if (!current) break;
      processed++;

      try {
        let node: CoreNode;
        try {
          const record = await sdkCore.resolveIpnsRecord(current.ipnsName, this.ctx);
          if (!record) continue;
          const raw = await sdkCore.fetchFromIpfs(this.ctx, record.cid);
          const published = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
          node = await unsealNode(published, current.readKey);
        } catch {
          continue;
        }

        for (const child of node.children ?? []) {
          if (visited.has(child.ipnsName)) continue;
          visited.add(child.ipnsName);

          try {
            const childRecord = await sdkCore.resolveIpnsRecord(child.ipnsName, this.ctx);
            if (!childRecord) throw new Error('child IPNS record not found');
            const rawChild = await sdkCore.fetchFromIpfs(this.ctx, childRecord.cid);
            const childPublished = JSON.parse(new TextDecoder().decode(rawChild)) as PublishedNode;
            const childReadKey = await unsealChildReadKey(
              child.readKeySealed,
              current.readKey,
              childPublished.id,
              childPublished.kind,
              child.generation
            );
            readableIpnsNames.push(child.ipnsName);
            queue.push({ ipnsName: child.ipnsName, readKey: childReadKey, isRoot: false });
          } catch {
            unreadableIpnsNames.push(child.ipnsName);
          }
        }
      } finally {
        // The children loop unseals with this key, so it may only be zeroed
        // after the loop (this queue entry is the key's terminal owner).
        if (!current.isRoot) current.readKey.fill(0);
      }
    }

    // The MAX_NODES cutoff can exit the loop with entries still queued --
    // zero their (never-dequeued, therefore never-finally'd) keys too.
    for (const remaining of queue) {
      if (!remaining.isRoot) remaining.readKey.fill(0);
    }

    return { readableIpnsNames, unreadableIpnsNames };
  }

  /**
   * Fire-and-forget wrapper around {@link enumerateMoveDescendants}. Never
   * blocks the caller (mirrors `fireAndForgetUnenroll`'s philosophy) and
   * never throws -- failures are logged, matching the non-critical warning
   * pattern used elsewhere in this file.
   */
  private enumerateMoveDescendantsFireAndForget(
    rootIpnsName: string,
    rootReadKey: Uint8Array,
    rootKind: PublishedNode['kind']
  ): void {
    // This wrapper receives a dedicated copy of the read key (see the moveItem
    // call site) and is its terminal owner (D-09) -- zero it on every exit
    // path, including the non-folder short-circuit and after the async walk
    // settles (the walk itself never zeroes its root key).
    if (rootKind !== 'folder' && rootKind !== 'root') {
      rootReadKey.fill(0);
      return;
    }
    this.enumerateMoveDescendants(rootIpnsName, rootReadKey, rootKind)
      .then(({ unreadableIpnsNames }) => {
        if (unreadableIpnsNames.length > 0) {
          console.warn(
            `[CipherBox] moveItem: ${unreadableIpnsNames.length} descendant(s) of ${rootIpnsName} ` +
              `could not be read after move (D-12):`,
            unreadableIpnsNames
          );
        }
      })
      .catch((err) => console.warn('[CipherBox] moveItem: descendant enumeration failed:', err))
      .finally(() => rootReadKey.fill(0));
  }

  /**
   * Create a new owned subfolder inside an existing folder.
   *
   * Mints an owned subfolder Node with its own write-body (ipnsPrivateKey +
   * empty writeChildren), publishes it at seq 1n, then inserts a
   * SealedChildRef into the parent read-body AND a WriteChildRef into the
   * parent write-body and republishes the parent (D-03). Adapts the
   * `createSharedSubfolder` build-path (shared-write.ts:288) to the owned
   * (non-share) write chain.
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

      // Reject duplicate sibling names — mirrors uploadFile's contract so folder
      // and file creation enforce the same uniqueness invariant.
      if (parent.children.some((child) => child.name === name)) {
        throw new Error('An item with this name already exists');
      }

      // Reconcile-before-publish (SC#3 / D-04): defer on any sequence mismatch.
      await this.reconcileFolderSequence(parentIpnsName, parent.sequenceNumber, parent.folderKey);

      // Preserve the parent's existing write chain — augmented below with the
      // new child's WriteChildRef.
      const parentWriteBodyParams = await this.getWriteBodyParams(parent);
      if (!parentWriteBodyParams.writeKey) {
        throw new Error(
          `createFolder: parent folder ${parentIpnsName} has no writeKey — cannot mint an owned subfolder without a write-capable parent`
        );
      }
      const parentWriteKey = parentWriteBodyParams.writeKey;
      const parentWriteChildren = parentWriteBodyParams.writeChildren ?? [];

      // Mint child keys — we own these until handed off to the caller / folderTree (D-09).
      let childReadKey: Uint8Array | null = generateRandomBytes(32);
      let childWriteKey: Uint8Array | null = generateRandomBytes(32);
      const childKeypair = generateEd25519Keypair();
      let childIpnsPrivateKey: Uint8Array | null = childKeypair.privateKey;

      try {
        const childIpnsName = await deriveIpnsName(childKeypair.publicKey);
        const childId = crypto.randomUUID();
        const now = Date.now();

        const childNode: CoreNode = {
          schema: 'node/v3',
          kind: 'folder',
          id: childId,
          generation: 0,
          createdAt: now,
          modifiedAt: now,
          children: [],
          writeBody: {
            ipnsPrivateKey: childIpnsPrivateKey,
            writeChildren: [],
          },
        };

        const childPublished = await sealNode(childNode, childReadKey, childWriteKey);

        // Compute TEE enrollment fields (if teeKeys configured) BEFORE any IPFS
        // upload — fail closed on incomplete config so a malformed teeKeys
        // short-circuits before the addToIpfs side effect and never leaves an
        // orphaned blob behind (mirrors createSubfolder, registration.ts:85-109).
        let encryptedIpnsPrivateKey: string | undefined;
        let keyEpoch: number | undefined;
        if (this.config.teeKeys) {
          const { currentPublicKey, currentEpoch } = this.config.teeKeys;
          if (!currentPublicKey) {
            throw new Error(
              'createFolder: teeKeys.currentPublicKey is missing or empty — refusing to publish un-enrolled subfolder'
            );
          }
          if (!Number.isInteger(currentEpoch) || currentEpoch < 1) {
            throw new Error(
              'createFolder: teeKeys.currentEpoch must be a positive integer (>= 1) — refusing to publish un-enrolled subfolder'
            );
          }
          // ECIES-wrap the freshly-minted childIpnsPrivateKey under the TEE
          // public key. Do NOT zero childIpnsPrivateKey here — wrapKey reads
          // but does not consume the buffer; it is zeroed below at its
          // existing terminal-owner site (D-09).
          const teePublicKeyBytes = hexToBytes(currentPublicKey);
          const wrappedBytes = await wrapKey(childIpnsPrivateKey, teePublicKeyBytes);
          encryptedIpnsPrivateKey = bytesToHex(wrappedBytes);
          keyEpoch = currentEpoch;
        }

        // First publish — sequenceNumber MUST be 1n (Phase-60 strict gate).
        await sdkCore.createAndPublishIpnsRecord({
          ipnsPrivateKey: childIpnsPrivateKey,
          ipnsName: childIpnsName,
          metadataCid: (
            await sdkCore.addToIpfs(
              this.ctx,
              new TextEncoder().encode(JSON.stringify(childPublished))
            )
          ).cid,
          sequenceNumber: 1n,
          ctx: this.ctx,
          encryptedIpnsPrivateKey,
          keyEpoch,
        });

        // Build the parent's SealedChildRef (read-body — no write field, NODE-03).
        const readKeySealed = await sealChildReadKey(
          childReadKey,
          parent.folderKey,
          childId,
          'folder',
          0
        );
        const childEntry: SealedChildRef = {
          name,
          ipnsName: childIpnsName,
          generation: 0,
          versionFloor: 1n,
          readKeySealed,
        };

        // Build the parent's WriteChildRef (write-body — role 0x04).
        const writeKeySealed = await sealChildWriteKey(
          childWriteKey,
          parentWriteKey,
          childId,
          'folder',
          0
        );
        const writeChildRef: WriteChildRef = { childId, writeKeySealed };

        const baseChildren = [...parent.children];
        const updatedChildren = [...parent.children, childEntry];
        const updatedWriteChildren = [...parentWriteChildren, writeChildRef];

        const { newSequenceNumber, publishedChildren, publishedWriteChildren } =
          await sdkCore.updateFolderMetadataAndPublish({
            children: updatedChildren,
            baseChildren,
            folderKey: parent.folderKey,
            writeKey: parentWriteKey,
            writeChildren: updatedWriteChildren,
            ipnsPrivateKey: parent.ipnsKeypair.privateKey,
            ipnsName: parentIpnsName,
            sequenceNumber: parent.sequenceNumber,
            ctx: this.ctx,
            nodeId: parent.nodeId,
            nodeGeneration: parent.nodeGeneration,
          });

        this.adoptPublishedFolderState(
          parent,
          publishedChildren,
          newSequenceNumber,
          publishedWriteChildren ?? updatedWriteChildren
        );

        // Register the new child so it is immediately usable (upload/rename/etc.)
        // without a reload round-trip.
        this.registerFolder(
          childIpnsName,
          childReadKey,
          { publicKey: childKeypair.publicKey, privateKey: childIpnsPrivateKey },
          [],
          1n,
          childId,
          0,
          childWriteKey
        );

        this.emitter.emit({
          type: 'folder:updated',
          folderId: parentIpnsName,
          ipnsName: parentIpnsName,
          children: await this.resolveListingChildren(
            publishedChildren,
            parent.folderKey,
            parentIpnsName,
            newSequenceNumber
          ),
          sequenceNumber: newSequenceNumber,
        });

        // Scope-exit rotation (SC#2/SC#4): the parent's read chain may need
        // rotation now that a new child scope has been entered under it.
        await this.performScopeExitRotation({
          ancestorIpnsNames: [parentIpnsName],
          rootNodeIpnsName: parentIpnsName,
          rootNodeId: parent.nodeId,
          rootReadKey: parent.folderKey,
          rootIpnsPrivateKey: parent.ipnsKeypair.privateKey,
          rootIpnsPublicKey: parent.ipnsKeypair.publicKey,
        });

        // registerFolder() made its own defensive copies (D-09), so a copy
        // handed back to the caller here is independent of the local buffers
        // this function zeroes below.
        const result = {
          id: childId,
          ipnsName: childIpnsName,
          folderKey: new Uint8Array(childReadKey),
          ipnsPrivateKey: new Uint8Array(childIpnsPrivateKey),
        };

        childReadKey.fill(0);
        childReadKey = null;
        childWriteKey.fill(0);
        childWriteKey = null;
        childIpnsPrivateKey.fill(0);
        childIpnsPrivateKey = null;

        return result;
      } catch (err) {
        // Zero minted keys on failure — never zero caller-supplied keys (D-09).
        childReadKey?.fill(0);
        childWriteKey?.fill(0);
        childIpnsPrivateKey?.fill(0);
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

      // 1b. Reconcile-before-publish (SC#3 / D-04): defer on any sequence
      // mismatch, never publish (metadata OR rotation) against possibly-superseded state.
      await this.reconcileFolderSequence(folderIpnsName, folder.sequenceNumber, folder.folderKey);

      // 1c. Preserve the folder's existing write-body on republish (D-03).
      const writeBodyParams = await this.getWriteBodyParams(folder);

      // 2. Publish updated metadata
      const { newSequenceNumber, publishedChildren, publishedWriteChildren } =
        await sdkCore.updateFolderMetadataAndPublish({
          children: updatedChildren,
          baseChildren,
          folderKey: folder.folderKey,
          ...writeBodyParams,
          ipnsPrivateKey: folder.ipnsKeypair.privateKey,
          ipnsName: folderIpnsName,
          sequenceNumber: folder.sequenceNumber,
          ctx: this.ctx,
          nodeId: folder.nodeId,
          nodeGeneration: folder.nodeGeneration,
        });

      // 3. Update internal state — adopt merged published set (CR-01)
      this.adoptPublishedFolderState(
        folder,
        publishedChildren,
        newSequenceNumber,
        publishedWriteChildren ?? writeBodyParams.writeChildren
      );

      // 4. Emit update event
      this.emitter.emit({
        type: 'folder:updated',
        folderId: folderIpnsName,
        ipnsName: folderIpnsName,
        children: await this.resolveListingChildren(
          publishedChildren,
          folder.folderKey,
          folderIpnsName,
          newSequenceNumber
        ),
        sequenceNumber: newSequenceNumber,
      });

      // 5. Scope-exit rotation (SC#2/SC#4): rotate this folder's read chain when covered.
      await this.performScopeExitRotation({
        ancestorIpnsNames: [folderIpnsName],
        rootNodeIpnsName: folderIpnsName,
        rootNodeId: folder.nodeId,
        rootReadKey: folder.folderKey,
        rootIpnsPrivateKey: folder.ipnsKeypair.privateKey,
        rootIpnsPublicKey: folder.ipnsKeypair.publicKey,
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

      // Reconcile-before-publish (SC#3 / D-04): both folders are about to be
      // published; defer on ANY mismatch (source OR dest) rather than
      // publishing (metadata OR rotation) against possibly-superseded state.
      await this.reconcileFolderSequence(
        sourceIpnsName,
        sourceFolder.sequenceNumber,
        sourceFolder.folderKey
      );
      await this.reconcileFolderSequence(
        destIpnsName,
        destFolder.sequenceNumber,
        destFolder.folderKey
      );

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

        // D-12: best-effort, non-blocking enumeration of the moved subtree's
        // descendants so an unreadable one is surfaced (logged) instead of
        // silently dropped or mis-rotated. Never blocks the move itself. Pass
        // a defensive copy — the `finally` below zeroes the ORIGINAL
        // `childReadKey` before this fire-and-forget walk necessarily finishes.
        this.enumerateMoveDescendantsFireAndForget(
          movedRef.ipnsName,
          new Uint8Array(childReadKey),
          childPub.kind
        );
      } finally {
        // Zero the recovered child readKey on every exit path — engine-derived,
        // terminal-owned (D-09).
        childReadKey.fill(0);
      }

      // Preserve BOTH folders' existing write-bodies on republish (D-03).
      // 68.1-31: write-link re-homing is implemented HERE (previously
      // deferred to 68.1-02) — the moved child's WriteChildRef is unsealed
      // under the SOURCE writeKey, dropped from the source write-body, and
      // re-sealed under the DEST writeKey into the dest write-body, so the
      // moved item stays write-capable in its new location.
      const destWriteBodyParams = await this.getWriteBodyParams(destFolder);
      const sourceWriteBodyParams = await this.getWriteBodyParams(sourceFolder);

      // 68.1-31: write-link re-homing. Default to verbatim preservation;
      // only re-home when BOTH folders are write-capable (a read-plane-only
      // move must never throw or fabricate a write link under a zero/absent
      // key — T-68.1-01-03).
      let rehomedDestWriteChildren = destWriteBodyParams.writeChildren;
      let rehomedSourceWriteChildren = sourceWriteBodyParams.writeChildren;

      if (!destWriteBodyParams.writeKey || !sourceWriteBodyParams.writeKey) {
        console.warn(
          `moveItem: source or destination folder ${sourceIpnsName} -> ${destIpnsName} is read-only — the moved item will not be write-capable in its new location`
        );
      } else {
        // Write plane is keyed by node UUID (childPub.id, already resolved
        // above for the read-plane re-seal) — NEVER the ipnsName-based
        // `childId` param moveItem receives. The write-capability gate at
        // resolveFileWriteChainKeys matches on this exact UUID.
        const movedWriteRef = sourceWriteBodyParams.writeChildren?.find(
          (wc) => wc.childId === childPub.id
        );
        if (movedWriteRef) {
          let movedWriteKey: Uint8Array | null = null;
          try {
            // Generation is destEntry.generation — the SealedChildRef
            // parent-mirror generation, unchanged by the move (same value
            // the read-plane re-seal above uses).
            movedWriteKey = await unsealChildWriteKey(
              movedWriteRef.writeKeySealed,
              sourceWriteBodyParams.writeKey,
              childPub.id,
              childPub.kind,
              destEntry.generation
            );
            const writeKeySealed = await sealChildWriteKey(
              movedWriteKey,
              destWriteBodyParams.writeKey,
              childPub.id,
              childPub.kind,
              destEntry.generation
            );
            rehomedDestWriteChildren = [
              ...(destWriteBodyParams.writeChildren ?? []),
              { childId: childPub.id, writeKeySealed },
            ];
            rehomedSourceWriteChildren = (sourceWriteBodyParams.writeChildren ?? []).filter(
              (wc) => wc.childId !== childPub.id
            );
          } finally {
            // Zero the recovered child writeKey on every exit path —
            // engine-derived, terminal-owned (D-09). Never zero
            // sourceWriteBodyParams.writeKey / destWriteBodyParams.writeKey
            // (tree/caller-owned).
            movedWriteKey?.fill(0);
          }
        }
        // else: no source WriteChildRef for this child (pre-write-plane or
        // already read-only) — nothing to re-home, lists stay verbatim.
      }

      // D-12: publish DESTINATION before SOURCE (dest-before-source) so a
      // crash between publishes never orphans the moved node out of both
      // folders — folds the Phase-64 OUT-tagged
      // sdk-client-move-publish-durability work into this cutover.
      const {
        newSequenceNumber: dstSeq,
        publishedChildren: dstChildren,
        publishedWriteChildren: dstPublishedWriteChildren,
      } = await sdkCore.updateFolderMetadataAndPublish({
        children: updatedDest,
        baseChildren: baseDestChildren,
        readKey: destFolder.folderKey,
        writeKey: destWriteBodyParams.writeKey,
        writeChildren: rehomedDestWriteChildren,
        ipnsPrivateKey: destFolder.ipnsKeypair.privateKey,
        ipnsName: destIpnsName,
        sequenceNumber: destFolder.sequenceNumber,
        ctx: this.ctx,
        nodeId: destFolder.nodeId,
        nodeGeneration: destFolder.nodeGeneration,
      });

      this.adoptPublishedFolderState(
        destFolder,
        dstChildren,
        dstSeq,
        dstPublishedWriteChildren ?? rehomedDestWriteChildren
      );
      this.emitter.emit({
        type: 'folder:updated',
        folderId: destIpnsName,
        ipnsName: destIpnsName,
        children: await this.resolveListingChildren(
          dstChildren,
          destFolder.folderKey,
          destIpnsName,
          dstSeq
        ),
        sequenceNumber: dstSeq,
      });

      // Publish updated source folder
      const {
        newSequenceNumber: srcSeq,
        publishedChildren: srcChildren,
        publishedWriteChildren: srcPublishedWriteChildren,
      } = await sdkCore.updateFolderMetadataAndPublish({
        children: updatedSource,
        baseChildren: baseSourceChildren,
        readKey: sourceFolder.folderKey,
        writeKey: sourceWriteBodyParams.writeKey,
        writeChildren: rehomedSourceWriteChildren,
        ipnsPrivateKey: sourceFolder.ipnsKeypair.privateKey,
        ipnsName: sourceIpnsName,
        sequenceNumber: sourceFolder.sequenceNumber,
        ctx: this.ctx,
        nodeId: sourceFolder.nodeId,
        nodeGeneration: sourceFolder.nodeGeneration,
      });

      this.adoptPublishedFolderState(
        sourceFolder,
        srcChildren,
        srcSeq,
        srcPublishedWriteChildren ?? rehomedSourceWriteChildren
      );
      this.emitter.emit({
        type: 'folder:updated',
        folderId: sourceIpnsName,
        ipnsName: sourceIpnsName,
        children: await this.resolveListingChildren(
          srcChildren,
          sourceFolder.folderKey,
          sourceIpnsName,
          srcSeq
        ),
        sequenceNumber: srcSeq,
      });

      // Scope-exit rotation (SC#2/SC#4): the moved child exits the SOURCE
      // folder's scope; rotate the source's read chain when covered. Moving
      // INTO the destination is a scope ENTRY, not an exit — no rotation is
      // needed there (the re-seal above already re-keys the moved node for dest).
      await this.performScopeExitRotation({
        ancestorIpnsNames: [sourceIpnsName],
        rootNodeIpnsName: sourceIpnsName,
        rootNodeId: sourceFolder.nodeId,
        rootReadKey: sourceFolder.folderKey,
        rootIpnsPrivateKey: sourceFolder.ipnsKeypair.privateKey,
        rootIpnsPublicKey: sourceFolder.ipnsKeypair.publicKey,
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

      // 1b. Reconcile-before-publish (SC#3 / D-04): defer on any sequence
      // mismatch, never publish (metadata OR rotation) against possibly-superseded state.
      await this.reconcileFolderSequence(folderIpnsName, folder.sequenceNumber, folder.folderKey);

      // 1c. Preserve the folder's existing write-body on republish (D-03), then
      // DROP the removed child's WriteChildRef so the write-chain shrinks in
      // step with the read-plane delete (SC#1). `childId` here is an ipnsName
      // (matched against SealedChildRef.ipnsName by sdkCore.deleteFromFolder
      // above); WriteChildRef.childId is the child's node UUID -- a DIFFERENT
      // value (72-RESEARCH.md Pitfall 1) -- so the removed item's UUID must be
      // resolved before it can be filtered out of writeChildren. The pre-trim
      // snapshot is threaded through as baseWriteChildren so a CAS-409 retry's
      // base-aware merge (registration.ts) prunes the drop instead of letting a
      // racing writer's stale remote snapshot resurrect it.
      const writeBodyParams = await this.getWriteBodyParams(folder);
      const baseWriteChildren = writeBodyParams.writeChildren;
      let trimmedWriteChildren = writeBodyParams.writeChildren;
      if (writeBodyParams.writeKey && writeBodyParams.writeChildren) {
        try {
          const removedResolved = await this.resolvePublishedNode(removedItem.ipnsName);
          const removedUuid = removedResolved?.published.id;
          if (removedUuid) {
            trimmedWriteChildren = writeBodyParams.writeChildren.filter(
              (wc) => wc.childId !== removedUuid
            );
          } else {
            console.warn(
              `[CipherBox] deleteItem: could not resolve removed item's UUID (${removedItem.ipnsName}) — skipping write-chain trim`
            );
          }
        } catch (err) {
          // Fail OPEN (Pitfall 2): this is a hygiene fix — a resolve miss on
          // the removed item's own IPNS record must never abort the
          // already-succeeded read-plane delete. Skip the write-chain trim
          // and proceed with the write-body unchanged.
          console.warn(
            `[CipherBox] deleteItem: UUID resolve failed for write-chain trim (${removedItem.ipnsName}):`,
            err
          );
        }
      }

      // 2. Publish updated metadata
      const { newSequenceNumber, publishedChildren, publishedWriteChildren } =
        await sdkCore.updateFolderMetadataAndPublish({
          children: updatedChildren,
          baseChildren,
          folderKey: folder.folderKey,
          writeKey: writeBodyParams.writeKey,
          writeChildren: trimmedWriteChildren,
          baseWriteChildren,
          ipnsPrivateKey: folder.ipnsKeypair.privateKey,
          ipnsName: folderIpnsName,
          sequenceNumber: folder.sequenceNumber,
          ctx: this.ctx,
          nodeId: folder.nodeId,
          nodeGeneration: folder.nodeGeneration,
        });

      // 3. Update internal state — adopt merged published set (CR-01)
      this.adoptPublishedFolderState(
        folder,
        publishedChildren,
        newSequenceNumber,
        publishedWriteChildren ?? trimmedWriteChildren
      );

      // 4. Emit update event
      this.emitter.emit({
        type: 'folder:updated',
        folderId: folderIpnsName,
        ipnsName: folderIpnsName,
        children: await this.resolveListingChildren(
          publishedChildren,
          folder.folderKey,
          folderIpnsName,
          newSequenceNumber
        ),
        sequenceNumber: newSequenceNumber,
      });

      // 5. Scope-exit rotation (SC#2/SC#4): rotate this folder's read chain when covered.
      await this.performScopeExitRotation({
        ancestorIpnsNames: [folderIpnsName],
        rootNodeIpnsName: folderIpnsName,
        rootNodeId: folder.nodeId,
        rootReadKey: folder.folderKey,
        rootIpnsPrivateKey: folder.ipnsKeypair.privateKey,
        rootIpnsPublicKey: folder.ipnsKeypair.publicKey,
      });

      // 6. Fire-and-forget IPNS unenrollment (resolve async collection then dispatch)
      this.collectRemovedItemIpnsNames(removedItem, folder.folderKey)
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
        // 2. Seal the v3 file Node's readKey (uploadResult.fileReadKey — NOT
        // the content fileKey, D-07/NODE-02) into the parent's read-body —
        // READ-03. childId is the file Node's own UUID (uploadResult.fileNodeId,
        // matches WriteChildRef.childId below).
        const baseChildren = [...folder.children];
        const { updatedChildren } = await sdkCore.addFilePointerToFolder({
          children: folder.children,
          childReadKey: uploadResult.fileReadKey,
          parentReadKey: folder.folderKey,
          childId: uploadResult.fileNodeId,
          childKind: 'file',
          childGeneration: 0,
          name: fileName,
          ipnsName: uploadResult.fileMetaIpnsName,
          versionFloor: 1n,
        });

        // 2b. Insert a WriteChildRef for the new file's writeKey into the
        // parent's write-body (68.1-09 owns WriteChildRef insertion for
        // owned uploads; 68.1-01's getWriteBodyParams sources the existing
        // chain to preserve verbatim). No real writeKey (legacy zero-fallback
        // parent, T-68.1-01-03) means the file cannot be write-linked — the
        // upload still succeeds read-only, matching getWriteBodyParams'
        // existing preservation-only contract at every other owned call site.
        const writeBodyParams = await this.getWriteBodyParams(folder);
        let updatedWriteChildren = writeBodyParams.writeChildren;
        if (writeBodyParams.writeKey) {
          const writeKeySealed = await sealChildWriteKey(
            uploadResult.fileWriteKey,
            writeBodyParams.writeKey,
            uploadResult.fileNodeId,
            'file',
            0
          );
          updatedWriteChildren = [
            ...(writeBodyParams.writeChildren ?? []),
            { childId: uploadResult.fileNodeId, writeKeySealed },
          ];
        }

        // 3. Concurrent: file IPNS batch publish + folder metadata update
        //    These two operations are independent -- no data dependency between them.
        //    Using Promise.allSettled to handle partial failures gracefully.
        const [batchResult, folderResult] = await Promise.allSettled([
          sdkCore.batchPublishIpnsRecords([uploadResult.ipnsRecord], this.ctx),
          sdkCore.updateFolderMetadataAndPublish({
            children: updatedChildren,
            baseChildren,
            folderKey: folder.folderKey,
            writeKey: writeBodyParams.writeKey,
            writeChildren: updatedWriteChildren,
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

        const { newSequenceNumber, publishedChildren, publishedWriteChildren } = folderResult.value;

        // 4. Update internal state — adopt merged published set (CR-01)
        this.adoptPublishedFolderState(
          folder,
          publishedChildren,
          newSequenceNumber,
          publishedWriteChildren ?? updatedWriteChildren
        );

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
          children: await this.resolveListingChildren(
            publishedChildren,
            folder.folderKey,
            folderIpnsName,
            newSequenceNumber
          ),
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
        // uploadResult.fileReadKey/fileWriteKey are caller-owned raw returns
        // (D-09) — this call site is the terminal owner: both are sealed into
        // the parent's read/write-body above and nothing downstream retains
        // them, so zero the local copies once consumed.
        clearBytes(uploadResult.fileReadKey);
        clearBytes(uploadResult.fileWriteKey);
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
        /** Plaintext byte size, captured pre-upload for the parent's SealedChildRef display mirror. */
        size: number;
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
            return {
              fileName: file.fileName,
              fileId,
              uploadResult,
              size: file.data.length,
            } as FileResult;
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
        // Re-read folder state (read-body children AND write-body mirror) to
        // mitigate the stale-children race. 68.1-22: the previous read-only
        // loadFolderMetadata refresh advanced children+sequence but left
        // folder.metadata.writeBody stale, so getWriteBodyParams below
        // published an OUTDATED write chain at the fresh sequence — silently
        // dropping WriteChildRefs added by other devices (surfaced as "not
        // write-capable (no WriteChildRef)" on the clobbered device).
        await this.refreshFolderStateFromNetwork(folder);
        const initialChildren = folder.children;
        const baseChildren = [...initialChildren];
        let mergedChildren = initialChildren;
        const freshSeq = folder.sequenceNumber;

        // Add FilePointers for all successful uploads (skip collisions gracefully)
        const registeredSuccesses: FileResult[] = [];
        for (const success of successes) {
          try {
            // v3 file Node read chain (D-07/NODE-02): the parent's SealedChildRef
            // must wrap the file Node's OWN readKey (fileReadKey, used later by
            // resolveFileMetadata's unsealChildReadKey + unsealNode to recover the
            // file's PublishedNode). It must NOT wrap the content-encryption key
            // (fileKey, used only to decrypt the file bytes themselves) -- these are
            // two independently-minted 32-byte keys. uploadFile()'s single-shot path
            // (above) already sealed fileReadKey correctly; this batch path had been
            // left on the pre-node/v3 field name since 68.1-07 introduced the split.
            const { updatedChildren } = await sdkCore.addFilePointerToFolder({
              children: mergedChildren,
              childReadKey: success.uploadResult.fileReadKey,
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

        // Preserve the folder's existing write-body on republish (D-03) AND
        // insert a WriteChildRef for each newly-uploaded file (68.1-29: this
        // batch path — the ONLY path the web upload UI calls — previously
        // never inserted WriteChildRefs, leaving every web-uploaded file
        // permanently not write-capable; editor saves failed with
        // "not write-capable (no WriteChildRef)" — conflict-detection 219,
        // full-workflow 6.5.3). Mirrors the single-file uploadFile path: no
        // real parent writeKey (legacy zero-fallback, T-68.1-01-03) means the
        // files stay read-only, matching that path's contract.
        const writeBodyParams = await this.getWriteBodyParams(folder);
        let updatedWriteChildren = writeBodyParams.writeChildren;
        if (writeBodyParams.writeKey) {
          const newWriteRefs: WriteChildRef[] = [];
          for (const success of registeredSuccesses) {
            const writeKeySealed = await sealChildWriteKey(
              success.uploadResult.fileWriteKey,
              writeBodyParams.writeKey,
              success.fileId,
              'file',
              0
            );
            newWriteRefs.push({ childId: success.fileId, writeKeySealed });
          }
          updatedWriteChildren = [...(writeBodyParams.writeChildren ?? []), ...newWriteRefs];
        }

        // Single folder publish + batch IPNS publish (concurrent)
        const ipnsRecords = registeredSuccesses.map((s) => s.uploadResult.ipnsRecord);
        const [folderResult, batchResult] = await Promise.allSettled([
          sdkCore.updateFolderMetadataAndPublish({
            children: mergedChildren,
            baseChildren,
            folderKey: folder.folderKey,
            writeKey: writeBodyParams.writeKey,
            writeChildren: updatedWriteChildren,
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

        const { newSequenceNumber, publishedChildren, publishedWriteChildren } = folderResult.value;

        // Update internal state — adopt merged published set (CR-01),
        // including the new files' WriteChildRefs (68.1-29)
        this.adoptPublishedFolderState(
          folder,
          publishedChildren,
          newSequenceNumber,
          publishedWriteChildren ?? updatedWriteChildren
        );

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
          children: await this.resolveListingChildren(
            publishedChildren,
            folder.folderKey,
            folderIpnsName,
            newSequenceNumber
          ),
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
        // Clear file keys for all uploads (including collision-failed ones).
        // fileReadKey is sealed into the parent's read-body and fileWriteKey
        // into the parent's write-body above (68.1-29) — this call site is
        // the terminal owner of both (D-09).
        for (const success of successes) {
          clearBytes(success.uploadResult.fileKey);
          clearBytes(success.uploadResult.fileReadKey);
          clearBytes(success.uploadResult.fileWriteKey);
        }
      }
    });
  }

  /**
   * Resolve the write-chain keys for an owned file identified by its per-file
   * IPNS name (`fileId`, matching `SealedChildRef.ipnsName` — the same
   * convention `deleteFromFolder`/`renameInFolder` use for `childId`) within
   * `folder`'s read-body.
   *
   * Mirrors the inline write-chain walk in `updateSharedFile` (68.1-08):
   * `id`/`kind` are the resolved `PublishedNode` envelope's plaintext fields
   * (NODE-03), used as the AAD inputs for `unsealChildReadKey`/
   * `unsealChildWriteKey` alongside the parent-mirror `childRef.generation`
   * (generation-source rule, §2.6). `nodeGeneration`/`originalCreatedAt` come
   * from unsealing the file's own current Node (read-body only needs
   * `fileReadKey`; `fileWriteKey` is required regardless since the caller
   * republishes the Node via `updateFileMetadata`).
   *
   * @throws if `fileId` has no matching child, the file IPNS is unresolvable,
   *   the file has no `WriteChildRef` in the parent's write-body (not
   *   write-capable), or the resolved node is not a file node.
   * @security Returns `fileReadKey`/`fileWriteKey`/`fileIpnsPrivateKey` RAW —
   *   the caller is the terminal owner (D-09) and must zero them after use
   *   (T-68.1-12-04: `fileIpnsPrivateKey` is recovered here from the current
   *   file Node's write-body as a byproduct of resolving `nodeGeneration`/
   *   `originalCreatedAt` — 68.1-09's `replaceFile`/`restoreFileVersion`/
   *   `deleteFileVersion` receive it from the caller instead and zero this
   *   copy unused; the new public `resolveFileIpnsPrivateKey` wrapper below
   *   returns it directly for callers that need to pre-resolve it, since
   *   NODE-03's frozen `SealedChildRef` schema gives the web layer no
   *   independent way to derive it (Rule 3 deviation, 68.1-12)).
   */
  private async resolveFileWriteChainKeys(
    folder: FolderState,
    fileId: string
  ): Promise<{
    fileReadKey: Uint8Array;
    fileWriteKey: Uint8Array;
    fileIpnsPrivateKey: Uint8Array;
    fileMetaIpnsName: string;
    fileSequenceNumber: bigint;
    nodeId: string;
    nodeGeneration: number;
    originalCreatedAt: number;
  }> {
    const childRef = folder.children.find((c) => c.ipnsName === fileId);
    if (!childRef) throw new Error(`File not found: ${fileId}`);

    const filePub = await this.resolvePublishedNode(childRef.ipnsName);
    if (!filePub) throw new Error(`Cannot resolve file IPNS ${childRef.ipnsName}`);

    const fileNodeId = filePub.published.id;
    const fileKind = filePub.published.kind;

    let fileReadKey: Uint8Array | null = null;
    let fileWriteKey: Uint8Array | null = null;
    try {
      fileReadKey = await unsealChildReadKey(
        childRef.readKeySealed,
        folder.folderKey,
        fileNodeId,
        fileKind,
        childRef.generation
      );

      const writeBodyParams = await this.getWriteBodyParams(folder);
      const writeChildRef = writeBodyParams.writeChildren?.find((wc) => wc.childId === fileNodeId);
      if (!writeBodyParams.writeKey || !writeChildRef) {
        throw new Error(`File ${fileId} is not write-capable (no WriteChildRef)`);
      }

      fileWriteKey = await unsealChildWriteKey(
        writeChildRef.writeKeySealed,
        writeBodyParams.writeKey,
        fileNodeId,
        fileKind,
        childRef.generation
      );

      const currentFileNode = await unsealNode(filePub.published, fileReadKey, fileWriteKey);
      if (
        currentFileNode.kind !== 'file' ||
        !currentFileNode.content ||
        !currentFileNode.writeBody
      ) {
        throw new Error(`Node ${fileId} is not a write-capable file node`);
      }

      const resultReadKey = fileReadKey;
      const resultWriteKey = fileWriteKey;
      // Ownership transferred to the caller (D-09) — do not zero in `finally`.
      fileReadKey = null;
      fileWriteKey = null;

      // Zero the decrypted content key now that the needed fields are read — this
      // function is its terminal owner (D-09): only keys + node metadata are
      // returned, content.fileKey is never handed to the caller, so don't leave it
      // live until GC (mirrors updateSharedSingleFile's finally cleanup).
      currentFileNode.content.fileKey?.fill(0);

      return {
        fileReadKey: resultReadKey,
        fileWriteKey: resultWriteKey,
        // T-68.1-12-04: unsealed as a byproduct above (writeBody requires
        // fileWriteKey to unseal) — see the docstring above for why this is
        // now returned alongside the read/write keys.
        fileIpnsPrivateKey: currentFileNode.writeBody.ipnsPrivateKey,
        fileMetaIpnsName: childRef.ipnsName,
        fileSequenceNumber: filePub.sequenceNumber,
        nodeId: fileNodeId,
        nodeGeneration: currentFileNode.generation,
        originalCreatedAt: currentFileNode.createdAt,
      };
    } finally {
      // Only reached on a failure path — a successful return nulled both
      // locals above.
      fileReadKey?.fill(0);
      fileWriteKey?.fill(0);
    }
  }

  /**
   * Resolve an owned file's own IPNS signing key (write-body `ipnsPrivateKey`)
   * so a caller can pre-resolve it before calling {@link replaceFile} /
   * {@link restoreFileVersion} / {@link deleteFileVersion} (68.1-09's "the
   * caller pre-resolves `fileIpnsPrivateKey`" contract — those three methods
   * do not derive it themselves; they only resolve `fileReadKey`/
   * `fileWriteKey` via {@link resolveFileWriteChainKeys}).
   *
   * The write-chain walk requires the parent folder's `writeKey`, which lives
   * ONLY inside `CipherBoxClient`'s internal `FolderState` (D-03) — the web
   * layer has no independent way to derive it (NODE-03's frozen
   * `SealedChildRef` carries no `ipnsPrivateKeyEncrypted`-style field the
   * pre-v3 model used to expose this through). This thin public wrapper over
   * the existing private write-chain walk is the only way to satisfy that
   * contract from `apps/web` (T-68.1-12-04, Rule 3 deviation).
   *
   * @param parentIpnsName - IPNS name of the folder containing the file
   * @param fileId - IPNS name of the file (`SealedChildRef.ipnsName`)
   * @security Returns `fileIpnsPrivateKey` RAW. When immediately passed into
   *   `replaceFile`/`restoreFileVersion`/`deleteFileVersion`, sdk-core
   *   `updateFileMetadata` becomes its terminal owner and zeroes it
   *   (T-47-01) — the caller must NOT also zero it in that case. If the
   *   caller does not pass it to one of those methods, the caller becomes
   *   the terminal owner and must zero it itself. This method's own
   *   `fileReadKey`/`fileWriteKey` derivations are zeroed here (D-09).
   */
  async resolveFileIpnsPrivateKey(parentIpnsName: string, fileId: string): Promise<Uint8Array> {
    return this.withOperation('resolveFileIpnsPrivateKey', async () => {
      const folder = await this.requireFolder(parentIpnsName);
      const fileKeys = await this.resolveFileWriteChainKeys(folder, fileId);
      fileKeys.fileReadKey.fill(0);
      fileKeys.fileWriteKey.fill(0);
      return fileKeys.fileIpnsPrivateKey;
    });
  }

  /**
   * Mint an ECIES-wrapped `encryptedWriteKey` for a WRITE-permission share or
   * invite of an OWNED item (68.1-18, SHARE-WRITE-KEY / WEB-03 / GAP-3).
   *
   * Under the node/v3 write-chain, an item's own writeKey is sealed inside its
   * PARENT's write-body (`WriteChildRef.writeKeySealed`, under the parent's
   * writeKey) — there is no way to derive it from the parent's readKey alone
   * (68.1-11's documented gap). This is the SDK-boundary primitive that closes
   * that gap: it walks the owned write-chain the same way
   * {@link resolveFileWriteChainKeys} does (parent writeKey ->
   * `WriteChildRef.writeKeySealed` -> item's own writeKey, keyed by the
   * item's plaintext `PublishedNode.id`/`kind`, NODE-03, and the PARENT-MIRROR
   * `SealedChildRef.generation` — generation-source rule, mirrors
   * `resolveChildNodeIdentity`'s readKey analog in
   * `apps/web/src/lib/crypto/key-wrapping.ts`), then ECIES-wraps the raw
   * writeKey for `recipientPublicKey` and returns only the wrapped hex — the
   * item's raw writeKey never crosses the SDK boundary into the web layer
   * (T-68.1-18-02).
   *
   * Fails closed (throws, never returns an empty/zero encrypted key) when the
   * parent has no write-capable `writeKey` or the item has no `WriteChildRef`
   * in the parent's write-body (T-68.1-18-01).
   *
   * @param parentIpnsName - IPNS name of the folder that owns `itemIpnsName`
   *   (i.e. the item is one of `parent.children`)
   * @param itemIpnsName - IPNS name of the shared item (file or folder)
   * @param recipientPublicKey - 65-byte uncompressed secp256k1 public key to
   *   wrap the item's writeKey for (the real recipient for a direct share, or
   *   an ephemeral keypair's public key for an invite link)
   * @returns Hex-encoded ECIES ciphertext (the live REST DTOs are hex-only,
   *   mirroring 68.1-11's `encryptedReadKey` convention — not base64)
   * @security The derived item writeKey is zeroed in `finally` immediately
   *   after wrapping (terminal owner, D-09) — it never survives past this
   *   call's own stack frame.
   */
  async resolveShareEncryptedWriteKey(
    parentIpnsName: string,
    itemIpnsName: string,
    recipientPublicKey: Uint8Array
  ): Promise<string> {
    return this.withOperation('resolveShareEncryptedWriteKey', async () => {
      const parent = await this.requireFolder(parentIpnsName, 'Parent folder');

      const writeBodyParams = await this.getWriteBodyParams(parent);
      if (!writeBodyParams.writeKey) {
        throw new Error(
          `resolveShareEncryptedWriteKey: parent folder ${parentIpnsName} has no writeKey — cannot mint a write grant without a write-capable parent`
        );
      }
      const parentWriteKey = writeBodyParams.writeKey;

      const childRef = parent.children.find((c) => c.ipnsName === itemIpnsName);
      if (!childRef) {
        throw new Error(
          `resolveShareEncryptedWriteKey: item ${itemIpnsName} not found in parent folder ${parentIpnsName}`
        );
      }

      const itemPub = await this.resolvePublishedNode(itemIpnsName);
      if (!itemPub) {
        throw new Error(`resolveShareEncryptedWriteKey: cannot resolve item IPNS ${itemIpnsName}`);
      }
      const itemNodeId = itemPub.published.id;
      const itemKind = itemPub.published.kind;

      const writeChildRef = writeBodyParams.writeChildren?.find((wc) => wc.childId === itemNodeId);
      if (!writeChildRef) {
        throw new Error(
          `resolveShareEncryptedWriteKey: item ${itemIpnsName} has no WriteChildRef in the parent write-body — cannot mint a write grant for an item with no write-chain entry`
        );
      }

      // Derived item writeKey — this call is its terminal owner (D-09), zeroed
      // in `finally` regardless of the wrapKey outcome.
      let itemWriteKey: Uint8Array | null = await unsealChildWriteKey(
        writeChildRef.writeKeySealed,
        parentWriteKey,
        itemNodeId,
        itemKind,
        childRef.generation
      );

      try {
        const wrapped = await wrapKey(itemWriteKey, recipientPublicKey);
        return bytesToHex(wrapped);
      } finally {
        itemWriteKey?.fill(0);
        itemWriteKey = null;
      }
    });
  }

  /**
   * Conditional folder re-publish for lazy IPNS-key migration (TEE key-epoch
   * rotation).
   *
   * `SealedChildRef` carries no `modifiedAt`/`ipnsPrivateKeyEncrypted` field
   * to bump under the v3 model (NODE-03 — field set is EXACTLY {name,
   * ipnsName, generation, versionFloor, readKeySealed}), so a file-content
   * publish never itself touches the parent folder. When
   * `migratedIpnsPrivateKeyEncrypted` is provided, this republishes the
   * folder's CURRENT children unchanged, threading the newly TEE-wrapped key
   * into the folder's OWN IPNS record enrollment
   * (`updateFolderMetadataAndPublish`'s `encryptedIpnsPrivateKey` param) —
   * i.e. this call site is what actually persists a folder-level lazy TEE
   * key migration, piggybacked on a file mutation instead of a dedicated
   * publish. No-op (folder children + sequence unchanged) when no migration
   * is pending — a file-only publish never advances the folder's own
   * sequence. Emits `folder:updated` from the current folderTree snapshot on
   * every call, so both branches leave a consistent emission. Mutates
   * `folder` in place on the migration branch; the caller does not need to
   * re-fetch it from `folderTree`.
   */
  private async maybeRepublishFolderForFileMigration(
    folderIpnsName: string,
    folder: FolderState,
    migratedIpnsPrivateKeyEncrypted?: string
  ): Promise<void> {
    if (migratedIpnsPrivateKeyEncrypted) {
      const baseChildren = [...folder.children];
      const writeBodyParams = await this.getWriteBodyParams(folder);
      const { newSequenceNumber, publishedChildren, publishedWriteChildren } =
        await sdkCore.updateFolderMetadataAndPublish({
          children: folder.children,
          baseChildren,
          folderKey: folder.folderKey,
          ...writeBodyParams,
          ipnsPrivateKey: folder.ipnsKeypair.privateKey,
          ipnsName: folderIpnsName,
          sequenceNumber: folder.sequenceNumber,
          ctx: this.ctx,
          nodeId: folder.nodeId,
          nodeGeneration: folder.nodeGeneration,
          encryptedIpnsPrivateKey: migratedIpnsPrivateKeyEncrypted,
        });

      this.adoptPublishedFolderState(
        folder,
        publishedChildren,
        newSequenceNumber,
        publishedWriteChildren ?? writeBodyParams.writeChildren
      );
    }

    const live = this.folderTree.get(folderIpnsName) ?? folder;
    this.emitter.emit({
      type: 'folder:updated',
      folderId: folderIpnsName,
      ipnsName: folderIpnsName,
      children: await this.resolveListingChildren(
        live.children,
        live.folderKey,
        folderIpnsName,
        live.sequenceNumber
      ),
      sequenceNumber: live.sequenceNumber,
    });
  }

  /**
   * Replace a file's content, owning the full publish + folderTree bookkeeping.
   *
   * Routes the web "file replace" path (formerly the `useFileOperations`
   * fire-and-forget "6b" block) through the client so the SDK `folderTree`
   * stays authoritative. Steps:
   *   1. Read the parent folder from `folderTree.get()` (self-healing via
   *      `requireFolder`) and resolve the file's write-chain keys.
   *   2. Publish the file's per-IPNS metadata via sdk-core `updateFileMetadata`
   *      (direct single-shot publish, 68.1-07). Capture `prunedCids` for the
   *      caller to unpin.
   *   3. Conditional folder re-publish — ONLY on `migratedIpnsPrivateKeyEncrypted`
   *      (lazy TEE-key migration piggybacked on this mutation); otherwise the
   *      folder's children/sequence are left untouched.
   *   4. Emit `folder:updated` from the current folderTree snapshot.
   *
   * Per locked decision 2 the caller pre-resolves `fileIpnsPrivateKey`,
   * `currentMetadata`, and `updates` (web tier owns key/service logic). This
   * method does NOT zero `fileIpnsPrivateKey` — sdk-core `updateFileMetadata`
   * zeroes it in its own finally on every exit path (T-47-01); the caller
   * owns any additional lifecycle. The write-chain `fileReadKey`/
   * `fileWriteKey` this method derives ARE zeroed here (D-09 — this method is
   * their terminal owner).
   *
   * @param parentIpnsName - IPNS name of the folder containing the file
   * @param fileId - IPNS name of the file (`SealedChildRef.ipnsName`) to replace
   * @param fileData - Pre-resolved key + metadata + content updates
   * @returns Pruned version CIDs the caller should unpin
   */
  async replaceFile(
    parentIpnsName: string,
    fileId: string,
    fileData: {
      fileIpnsPrivateKey: Uint8Array;
      currentMetadata: NodeContent;
      updates: sdkCore.UpdateFileContentParams;
      createVersion: boolean;
      maxVersionsPerFile?: number;
      migratedIpnsPrivateKeyEncrypted?: string;
    }
  ): Promise<{ prunedCids: string[] }> {
    return this.withOperation('replaceFile', async () => {
      const folder = await this.requireFolder(parentIpnsName);
      const fileKeys = await this.resolveFileWriteChainKeys(folder, fileId);

      try {
        const publishResult = await sdkCore.updateFileMetadata({
          fileIpnsPrivateKey: fileData.fileIpnsPrivateKey,
          fileReadKey: fileKeys.fileReadKey,
          fileWriteKey: fileKeys.fileWriteKey,
          fileMetaIpnsName: fileKeys.fileMetaIpnsName,
          fileSequenceNumber: fileKeys.fileSequenceNumber,
          nodeId: fileKeys.nodeId,
          nodeGeneration: fileKeys.nodeGeneration,
          originalCreatedAt: fileKeys.originalCreatedAt,
          currentMetadata: fileData.currentMetadata,
          updates: fileData.updates,
          createVersion: fileData.createVersion,
          maxVersionsPerFile: fileData.maxVersionsPerFile,
          ctx: this.ctx,
        });

        await this.maybeRepublishFolderForFileMigration(
          parentIpnsName,
          folder,
          fileData.migratedIpnsPrivateKeyEncrypted
        );

        return { prunedCids: publishResult.prunedCids };
      } finally {
        fileKeys.fileReadKey.fill(0);
        fileKeys.fileWriteKey.fill(0);
        // T-68.1-12-04: this walk's own fileIpnsPrivateKey is unused here —
        // the caller supplies fileData.fileIpnsPrivateKey instead. Zero it.
        fileKeys.fileIpnsPrivateKey.fill(0);
      }
    });
  }

  /**
   * Restore a previous version of a file, owning publish + folderTree bookkeeping.
   *
   * Mirrors the web `useFileVersions.handleRestoreVersion` control flow, routed
   * through the client so `folderTree` stays authoritative:
   *   1. Read the parent folder from `folderTree.get()` (self-healing via
   *      `requireFolder`) and resolve the file's write-chain keys.
   *   2. Publish the file's per-IPNS metadata via `updateFileMetadata` using the
   *      pre-resolved restored metadata (`updates`). Capture `prunedCids`.
   *   3. CONDITIONAL folder publish — only when `migratedIpnsPrivateKeyEncrypted`
   *      is provided (lazy TEE-key migration piggybacked on this mutation, see
   *      `maybeRepublishFolderForFileMigration`). Otherwise leave folder
   *      children + sequence unchanged (the file-only publish does not
   *      advance the folder sequence).
   *   4. Emit `folder:updated` reading back from the folderTree snapshot so
   *      both branches emit a consistent event.
   *
   * Per locked decision 2 the caller pre-resolves `fileIpnsPrivateKey`,
   * `currentMetadata`, and the restored `updates` (web tier owns the restore
   * service logic — deciding WHICH version becomes live and how `versions`
   * folds). This method does NOT zero `fileIpnsPrivateKey` —
   * `updateFileMetadata` owns zeroing (T-47-01). The write-chain
   * `fileReadKey`/`fileWriteKey` this method derives ARE zeroed here (D-09).
   *
   * @param parentIpnsName - IPNS name of the folder containing the file
   * @param fileId - IPNS name of the file (`SealedChildRef.ipnsName`) to restore
   * @param versionIndex - Index of the version being restored (caller-resolved;
   *   informational only here — the caller already folded it into `updates`)
   * @param params - Pre-resolved key + metadata + restored content updates
   * @returns Pruned version CIDs the caller should unpin
   */
  async restoreFileVersion(
    parentIpnsName: string,
    fileId: string,
    versionIndex: number,
    params: {
      fileIpnsPrivateKey: Uint8Array;
      currentMetadata: NodeContent;
      updates: sdkCore.UpdateFileContentParams;
      createVersion?: boolean;
      maxVersionsPerFile?: number;
      migratedIpnsPrivateKeyEncrypted?: string;
    }
  ): Promise<{ prunedCids: string[] }> {
    void versionIndex;
    return this.withOperation('restoreFileVersion', async () => {
      const folder = await this.requireFolder(parentIpnsName);
      const fileKeys = await this.resolveFileWriteChainKeys(folder, fileId);

      try {
        const publishResult = await sdkCore.updateFileMetadata({
          fileIpnsPrivateKey: params.fileIpnsPrivateKey,
          fileReadKey: fileKeys.fileReadKey,
          fileWriteKey: fileKeys.fileWriteKey,
          fileMetaIpnsName: fileKeys.fileMetaIpnsName,
          fileSequenceNumber: fileKeys.fileSequenceNumber,
          nodeId: fileKeys.nodeId,
          nodeGeneration: fileKeys.nodeGeneration,
          originalCreatedAt: fileKeys.originalCreatedAt,
          currentMetadata: params.currentMetadata,
          updates: params.updates,
          createVersion: params.createVersion ?? false,
          maxVersionsPerFile: params.maxVersionsPerFile,
          ctx: this.ctx,
        });

        await this.maybeRepublishFolderForFileMigration(
          parentIpnsName,
          folder,
          params.migratedIpnsPrivateKeyEncrypted
        );

        return { prunedCids: publishResult.prunedCids };
      } finally {
        fileKeys.fileReadKey.fill(0);
        fileKeys.fileWriteKey.fill(0);
        // T-68.1-12-04: this walk's own fileIpnsPrivateKey is unused here —
        // the caller supplies params.fileIpnsPrivateKey instead. Zero it.
        fileKeys.fileIpnsPrivateKey.fill(0);
      }
    });
  }

  /**
   * Delete a specific past version from a file's history, owning publish +
   * folderTree bookkeeping.
   *
   * Mirrors the web `useFileVersions.handleDeleteVersion` control flow. Same
   * shape as {@link restoreFileVersion}: resolve write-chain keys, publish
   * file metadata via `updateFileMetadata`, conditional folder publish only
   * on lazy TEE-key migration, then emit `folder:updated` from the
   * folderTree snapshot. `updates` carries the SAME live content descriptor
   * as `currentMetadata` (the deleted version is a past entry, not the live
   * content) with the target version already pruned from its `versions`
   * array by the caller — `createVersion` is always `false` here since a
   * version-history edit never folds a new version.
   *
   * Per locked decision 2 the caller pre-resolves `fileIpnsPrivateKey`,
   * `currentMetadata`, the version-pruned `updates`, and the `deletedCid` (web
   * tier owns the delete service logic). This method does NOT zero
   * `fileIpnsPrivateKey` — `updateFileMetadata` owns zeroing (T-47-01). The
   * write-chain `fileReadKey`/`fileWriteKey` this method derives ARE zeroed
   * here (D-09).
   *
   * @param parentIpnsName - IPNS name of the folder containing the file
   * @param fileId - IPNS name of the file (`SealedChildRef.ipnsName`) whose version is deleted
   * @param versionIndex - Index of the version being deleted (caller-resolved;
   *   informational only here — the caller already pruned it from `updates`)
   * @param params - Pre-resolved key + metadata + version-pruned updates + deletedCid
   * @returns The deleted version's `deletedCid` plus any `prunedCids` `updateFileMetadata`
   *   reports (68.1-07's single-shot publish performs no CAS retry/merge, so this is
   *   ordinarily empty) — the caller must unpin both.
   */
  async deleteFileVersion(
    parentIpnsName: string,
    fileId: string,
    versionIndex: number,
    params: {
      fileIpnsPrivateKey: Uint8Array;
      currentMetadata: NodeContent;
      updates: sdkCore.UpdateFileContentParams;
      deletedCid?: string;
      maxVersionsPerFile?: number;
      migratedIpnsPrivateKeyEncrypted?: string;
    }
  ): Promise<{ deletedCid?: string; prunedCids: string[] }> {
    void versionIndex;
    return this.withOperation('deleteFileVersion', async () => {
      const folder = await this.requireFolder(parentIpnsName);
      const fileKeys = await this.resolveFileWriteChainKeys(folder, fileId);

      try {
        const publishResult = await sdkCore.updateFileMetadata({
          fileIpnsPrivateKey: params.fileIpnsPrivateKey,
          fileReadKey: fileKeys.fileReadKey,
          fileWriteKey: fileKeys.fileWriteKey,
          fileMetaIpnsName: fileKeys.fileMetaIpnsName,
          fileSequenceNumber: fileKeys.fileSequenceNumber,
          nodeId: fileKeys.nodeId,
          nodeGeneration: fileKeys.nodeGeneration,
          originalCreatedAt: fileKeys.originalCreatedAt,
          currentMetadata: params.currentMetadata,
          updates: params.updates,
          createVersion: false,
          maxVersionsPerFile: params.maxVersionsPerFile,
          ctx: this.ctx,
        });

        await this.maybeRepublishFolderForFileMigration(
          parentIpnsName,
          folder,
          params.migratedIpnsPrivateKeyEncrypted
        );

        return { deletedCid: params.deletedCid, prunedCids: publishResult.prunedCids };
      } finally {
        fileKeys.fileReadKey.fill(0);
        fileKeys.fileWriteKey.fill(0);
        // T-68.1-12-04: this walk's own fileIpnsPrivateKey is unused here —
        // the caller supplies params.fileIpnsPrivateKey instead. Zero it.
        fileKeys.fileIpnsPrivateKey.fill(0);
      }
    });
  }

  /**
   * Resolve a file Node's decrypted content metadata WITHOUT downloading or
   * decrypting its body.
   *
   * Recovers the file's OWN readKey from its `SealedChildRef` (sealed under the
   * parent folder's readKey — generation-source rule uses `fileRef.generation`,
   * the parent mirror, per Pitfall 3), then delegates to sdk-core's
   * `resolveFileMetadata` to resolve + fetch + unseal the file's `NodeContent`.
   * This is the read-only counterpart to {@link downloadFromIpns} (shares its
   * exact resolve/unseal steps) for callers that only need file metadata
   * (size, versions, mimeType, cid) — not the plaintext content itself. Added
   * (68.2-11, Rule 2) as the SDK facade replacement for the deleted web-native
   * `resolveFileMetadata` (file-metadata.service.ts).
   *
   * @param fileRef - The file's SealedChildRef from the parent folder's
   *   read-body (carries `readKeySealed` + `generation`)
   * @param folderKey - The PARENT folder's readKey (used to unseal the file's
   *   own readKey from `fileRef.readKeySealed`)
   * @returns The file's decrypted `NodeContent` plus its resolved metadata CID
   * @security `fileReadKey` is minted internally (recovered from the
   *   read-chain) and zeroed on every exit path (D-09). The returned
   *   `metadata.fileKey` is caller-owned and NOT zeroed here — matches
   *   sdk-core's `resolveFileMetadata` / the deleted web
   *   `file-metadata.service.ts`.
   */
  async resolveFileMetadata(
    fileRef: SealedChildRef,
    folderKey: Uint8Array
  ): Promise<{ metadata: NodeContent; metadataCid: string }> {
    return this.withOperation('resolveFileMetadata', async () => {
      const resolvedNode = await this.resolvePublishedNode(fileRef.ipnsName);
      if (!resolvedNode) {
        throw new Error(`resolveFileMetadata: IPNS record not found for ${fileRef.ipnsName}`);
      }

      // Terminal owner (D-09): zeroed after sdkCore.resolveFileMetadata unseals with it.
      let fileReadKey: Uint8Array | null = await unsealChildReadKey(
        fileRef.readKeySealed,
        folderKey,
        resolvedNode.published.id,
        'file',
        fileRef.generation
      );

      try {
        return await sdkCore.resolveFileMetadata(fileRef.ipnsName, fileReadKey, this.ctx);
      } finally {
        fileReadKey.fill(0);
        fileReadKey = null;
      }
    });
  }

  /**
   * Download a file using its per-file IPNS metadata.
   *
   * Recovers the file's OWN readKey from its `SealedChildRef` (sealed under the
   * parent folder's readKey — the generation-source rule uses `fileRef.
   * generation`, the parent mirror), resolves the file Node
   * (`resolveFileMetadata`, 68.1-07), decrypts its `NodeContent`, then fetches +
   * decrypts the encrypted content with the raw (non-ECIES-wrapped) `fileKey`
   * (D-07/NODE-02, GCM or CTR per `encryptionMode`).
   *
   * 68.1-22 FIX: the previous signature took a bare `folderKey` and passed it
   * straight to `sdkCore.resolveFileMetadata` as the file readKey. sdk-core
   * unseals the file Node directly under that key, so passing the PARENT folder
   * key (which every web call site did) always threw `CryptoError: Decryption
   * failed`. The method now takes the file's `SealedChildRef` + the parent
   * folderKey and recovers the file readKey the same way the web-native
   * `resolveFileMetadata` (file-metadata.service.ts, 68.1-04) does.
   *
   * @param fileRef - The file's SealedChildRef from the parent folder's
   *   read-body (carries `readKeySealed` + `generation`)
   * @param folderKey - The PARENT folder's readKey (used to unseal the file's
   *   own readKey from `fileRef.readKeySealed`)
   * @param onProgress - Optional download progress callback
   * @returns Decrypted file content
   */
  async downloadFromIpns(
    fileRef: SealedChildRef,
    folderKey: Uint8Array,
    onProgress?: DownloadProgressCallback
  ): Promise<Uint8Array> {
    return this.withOperation('downloadFromIpns', async () => {
      // Resolve the file Node once to recover its plaintext `id` (the AAD input
      // for unsealChildReadKey — matches the web-native resolveFileMetadata).
      const resolvedNode = await this.resolvePublishedNode(fileRef.ipnsName);
      if (!resolvedNode) {
        throw new Error(`downloadFromIpns: IPNS record not found for ${fileRef.ipnsName}`);
      }

      // Recover the file's OWN readKey from the parent-sealed SealedChildRef.
      // Terminal owner (D-09): zeroed after resolveFileMetadata unseals with it.
      let fileReadKey: Uint8Array | null = await unsealChildReadKey(
        fileRef.readKeySealed,
        folderKey,
        resolvedNode.published.id,
        'file',
        fileRef.generation
      );

      let metadata: NodeContent;
      try {
        ({ metadata } = await sdkCore.resolveFileMetadata(fileRef.ipnsName, fileReadKey, this.ctx));
      } finally {
        fileReadKey.fill(0);
        fileReadKey = null;
      }

      try {
        return await sdkCore.downloadFileContent({
          cid: metadata.cid,
          fileKey: metadata.fileKey,
          fileIv: metadata.fileIv,
          encryptionMode: metadata.encryptionMode,
          ctx: this.ctx,
          onProgress,
        });
      } finally {
        // T-68.1-09-04: zero the recovered raw fileKey after decrypt — it is
        // freshly recovered here (not caller-owned), so this call site is its
        // terminal owner. Never zero `folderKey` (caller-owned, D-09).
        clearBytes(metadata.fileKey);
      }
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

  // ---- IPFS transport (raw) ----

  /**
   * Upload raw (already-encrypted) bytes to IPFS via the backend relay.
   *
   * This is the mediated entrypoint for callers that need direct IPFS
   * transport access without the full file-metadata orchestration that
   * `uploadFile`/`uploadFiles` perform (e.g. BYO-pinning config blobs,
   * device-registry blobs). Progress is forwarded verbatim to the underlying
   * `sdkCore.addToIpfs` call so upload-progress UI keeps working (D-07 write
   * scope; RESEARCH Open Q2). Does not zero `encryptedData` — caller-supplied
   * buffers are never zeroed here (D-09, caller is terminal owner).
   *
   * @param encryptedData - Pre-encrypted bytes to upload
   * @param onProgress - Optional upload progress callback (percent 0-100)
   * @returns The resulting CID and size
   */
  async uploadBytes(
    encryptedData: Uint8Array,
    onProgress?: ProgressCallback
  ): Promise<{ cid: string; size: number }> {
    return this.withOperation('uploadBytes', async () => {
      const result = await sdkCore.addToIpfs(this.ctx, encryptedData, onProgress);
      return { cid: result.cid, size: result.size };
    });
  }

  /**
   * Download raw (still-encrypted) bytes from IPFS via the backend relay.
   *
   * Mediated entrypoint for direct IPFS transport reads (no metadata/key
   * resolution) — the raw counterpart to `uploadBytes`. Progress is
   * forwarded verbatim to `sdkCore.fetchFromIpfs` so download-progress UI
   * keeps working (D-07 write scope; RESEARCH Open Q2).
   *
   * @param cid - IPFS CID to fetch
   * @param onProgress - Optional download progress callback (loaded, total)
   * @returns The fetched (still-encrypted) bytes
   */
  async downloadBytes(cid: string, onProgress?: DownloadProgressCallback): Promise<Uint8Array> {
    return this.withOperation('downloadBytes', async () => {
      return sdkCore.fetchFromIpfs(this.ctx, cid, onProgress);
    });
  }

  /**
   * Unpin a CID from IPFS via the backend relay.
   *
   * Mediated entrypoint for direct IPFS transport unpin calls (e.g. cleanup
   * after a superseded config/registry blob publish).
   *
   * @param cid - IPFS CID to unpin
   */
  async unpin(cid: string): Promise<void> {
    return this.withOperation('unpin', async () => {
      await sdkCore.unpinFromIpfs(this.ctx, cid);
    });
  }

  // ---- Vault bootstrap (D-07 full boundary: auth-bootstrap crypto facade) ----

  /**
   * Generate a brand-new vault's root keys for a first-time user.
   *
   * Thin passthrough to `@cipherbox/core`'s `initializeVault` -- mints two
   * independent random `rootReadKey`/`rootWriteKey` AES keys plus the
   * deterministic `rootIpnsKeypair` derived from `userPrivateKey`. The
   * returned `VaultInit` is handed to the caller, who becomes its terminal
   * owner (D-09): this facade does not zero anything on success, matching
   * `initializeVault`'s own passthrough contract.
   *
   * @param userPrivateKey - 32-byte secp256k1 private key (caller-owned, never zeroed here)
   * @returns Freshly minted `VaultInit` (rootReadKey, rootWriteKey, rootIpnsKeypair)
   */
  async bootstrapVaultKeys(userPrivateKey: Uint8Array): Promise<VaultInit> {
    return this.withOperation('bootstrapVaultKeys', async () => {
      return initializeVault(userPrivateKey);
    });
  }

  /**
   * ECIES-wrap a `VaultInit`'s root keys under `userPublicKey` and serialize
   * them as the v3 vault key blob ready for IPFS upload.
   *
   * Combines `@cipherbox/core`'s `encryptVaultKeys` + `serializeVaultBlobV3`
   * into a single facade call (mirrors the exact two-step sequence
   * `useAuth.ts`'s new-user path performs today). The returned blob carries
   * only ciphertext -- no zeroing needed.
   *
   * @param vault - Plaintext `VaultInit` from `bootstrapVaultKeys`
   * @param userPublicKey - 65-byte uncompressed secp256k1 public key
   * @returns The v3 vault key blob bytes
   */
  async serializeVault(vault: VaultInit, userPublicKey: Uint8Array): Promise<Uint8Array> {
    return this.withOperation('serializeVault', async () => {
      const encrypted = await encryptVaultKeys(vault, userPublicKey);
      return serializeVaultBlobV3(encrypted.encryptedRootReadKey, encrypted.encryptedRootWriteKey);
    });
  }

  /**
   * Deserialize a v3 vault key blob fetched from IPFS and ECIES-unwrap both
   * root keys under `userPrivateKey`.
   *
   * Combines `@cipherbox/core`'s `deserializeVaultBlobV3` with two
   * `unwrapKey` calls (mirrors `useAuth.ts`'s existing-user load path). The
   * caller becomes the terminal owner of the returned plaintext keys
   * (D-09) -- but if the SECOND `unwrapKey` call fails after the first
   * succeeds, the already-unwrapped `rootReadKey` is zeroed before
   * propagating the error so a half-unwrapped vault key never lingers in
   * memory (T-68.2-09).
   *
   * @param blobBytes - The v3 vault key blob fetched from IPFS
   * @param userPrivateKey - 32-byte secp256k1 private key (caller-owned, never zeroed here)
   * @returns The decrypted `rootReadKey`/`rootWriteKey`
   */
  async deserializeVault(
    blobBytes: Uint8Array,
    userPrivateKey: Uint8Array
  ): Promise<{ rootReadKey: Uint8Array; rootWriteKey: Uint8Array }> {
    return this.withOperation('deserializeVault', async () => {
      const { encryptedRootReadKey, encryptedRootWriteKey } = deserializeVaultBlobV3(blobBytes);
      const rootReadKey = await unwrapKey(encryptedRootReadKey, userPrivateKey);
      try {
        const rootWriteKey = await unwrapKey(encryptedRootWriteKey, userPrivateKey);
        return { rootReadKey, rootWriteKey };
      } catch (error) {
        clearBytes(rootReadKey);
        throw error;
      }
    });
  }

  /**
   * Publish a brand-new user's empty root Node (D-03 / WEB-01/WEB-02).
   *
   * Thin passthrough to `sdkCore.publishEmptyRootNode` with `this.ctx`
   * injected -- the sdk-core primitive already documents that it does NOT
   * zero `rootIpnsKeypair.privateKey`/`rootReadKey`/`rootWriteKey` (caller
   * is the terminal owner, D-09); this facade preserves that contract.
   *
   * @returns The root's IPNS name, the underlying Node's UUID, and sequenceNumber 1n
   */
  async publishEmptyRootNode(params: {
    rootIpnsKeypair: { publicKey: Uint8Array; privateKey: Uint8Array };
    rootReadKey: Uint8Array;
    rootWriteKey: Uint8Array;
    teeKeys?: TeeKeys;
  }): Promise<{ ipnsName: string; nodeId: string; sequenceNumber: bigint }> {
    return this.withOperation('publishEmptyRootNode', async () => {
      return sdkCore.publishEmptyRootNode({ ...params, ctx: this.ctx });
    });
  }

  // ---- Device registry (D-07 full boundary: registry crypto facade) ----

  /**
   * Derive the deterministic Ed25519 IPNS keypair for the device registry.
   *
   * Thin passthrough to `@cipherbox/core`'s `deriveRegistryIpnsKeypair` --
   * mints a fresh keypair from `userPrivateKey` (caller-owned) and returns
   * it to the caller, who becomes its terminal owner (D-09).
   *
   * @param userPrivateKey - 32-byte secp256k1 private key (caller-owned, never zeroed here)
   */
  async deriveRegistryIpnsKeypair(
    userPrivateKey: Uint8Array
  ): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array; ipnsName: string }> {
    return this.withOperation('deriveRegistryIpnsKeypair', async () => {
      return deriveRegistryIpnsKeypair(userPrivateKey);
    });
  }

  /**
   * Encrypt (ECIES) a `DeviceRegistry` for IPFS storage.
   *
   * Thin passthrough to `@cipherbox/core`'s `encryptRegistry`. The
   * underlying primitive already zeroes its own intermediate plaintext
   * JSON buffer in a `finally` block -- no additional zeroing needed here.
   */
  async encryptRegistry(registry: DeviceRegistry, userPublicKey: Uint8Array): Promise<Uint8Array> {
    return this.withOperation('encryptRegistry', async () => {
      return encryptRegistry(registry, userPublicKey);
    });
  }

  /**
   * Decrypt (ECIES) a `DeviceRegistry` blob fetched from IPFS.
   *
   * Thin passthrough to `@cipherbox/core`'s `decryptRegistry`. The
   * underlying primitive already zeroes its own intermediate plaintext
   * buffer in a `finally` block -- no additional zeroing needed here.
   */
  async decryptRegistry(
    encrypted: Uint8Array,
    userPrivateKey: Uint8Array
  ): Promise<DeviceRegistry> {
    return this.withOperation('decryptRegistry', async () => {
      return decryptRegistry(encrypted, userPrivateKey);
    });
  }

  // ---- BYO-pinning (config-blob passthrough, D-07 full boundary) ----
  //
  // The BYO-pinning config blob (and any other user-configured settings
  // blob, e.g. the vault-settings blob) is NOT part of the ROT-07 durable
  // anti-rollback floor: it is a user-configured settings entry, not a
  // rotation-governed folder/file node (68.2-PATTERNS.md "No Analog
  // Found"). These methods are therefore thin 1:1 passthroughs with no
  // `rotationHighWater.enforceResolved` gating -- `sdkCore.resolveIpnsRecord`
  // still performs its own Ed25519 signature verification internally
  // (fail-closed on tampered records), just not the durable floor check.
  // Raw IPFS fetch/upload for the config blob's bytes are already covered
  // generically by `downloadBytes`/`uploadBytes` above -- no config-blob-
  // specific duplicates are needed for those two operations.

  /**
   * Test connectivity to a BYO-IPFS endpoint and auto-detect its protocol
   * (Kubo / Pinata / PSA).
   *
   * Thin passthrough to `sdkCore.testConnection` -- a pure network probe,
   * no crypto/IO through the client's own IPFS transport.
   */
  async testConnection(endpoint: string, authToken?: string): Promise<ConnectionTestResult> {
    return this.withOperation('testConnection', async () => {
      return sdkCore.testConnection(endpoint, authToken);
    });
  }

  /**
   * Resolve a config-blob IPNS record (BYO-pinning settings, or any other
   * user-configured blob backed by its own dedicated IPNS name).
   *
   * Thin passthrough to `sdkCore.resolveIpnsRecord` with `this.ctx`
   * injected -- see the section note above for why this is NOT routed
   * through the ROT-07 durable floor gate.
   */
  async resolveConfigBlob(
    ipnsName: string
  ): Promise<{ cid: string; sequenceNumber: bigint; signatureVerified: boolean } | null> {
    return this.withOperation('resolveConfigBlob', async () => {
      return sdkCore.resolveIpnsRecord(ipnsName, this.ctx);
    });
  }

  /**
   * Publish a config-blob IPNS record (BYO-pinning settings, or any other
   * user-configured blob).
   *
   * Thin passthrough to `sdkCore.createAndPublishIpnsRecord` with
   * `this.ctx` injected -- same no-gate rationale as `resolveConfigBlob`.
   */
  async publishConfigBlob(params: {
    ipnsPrivateKey: Uint8Array;
    ipnsPublicKey?: Uint8Array;
    ipnsName: string;
    metadataCid: string;
    sequenceNumber: bigint;
    encryptedIpnsPrivateKey?: string;
    keyEpoch?: number;
  }): Promise<{ success: boolean; sequenceNumber: bigint }> {
    return this.withOperation('publishConfigBlob', async () => {
      return sdkCore.createAndPublishIpnsRecord({ ...params, ctx: this.ctx });
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
      const folder = await this.requireFolder(folderIpnsName);

      // Reconcile-before-publish (SC#3 / D-04): addToBin publishes the parent
      // folder internally, so the check must run BEFORE calling it -- defer on
      // any sequence mismatch rather than publishing (metadata OR rotation)
      // against possibly-superseded state.
      await this.reconcileFolderSequence(folderIpnsName, folder.sequenceNumber, folder.folderKey);

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
        children: folderState
          ? await this.resolveListingChildren(
              folderState.children,
              folderState.folderKey,
              folderIpnsName,
              folderState.sequenceNumber
            )
          : [],
        sequenceNumber: folderState?.sequenceNumber ?? 0n,
      });
      this.emitter.emit({ type: 'bin:updated', entries: updatedBinState.entries });

      // Scope-exit rotation (SC#2/SC#4): the deleted item exits this folder's
      // scope; rotate its read chain when covered. folder.folderKey/nodeId/
      // ipnsKeypair are unaffected by a bin delete (only children/sequenceNumber
      // change), so the pre-addToBin snapshot remains valid here.
      await this.performScopeExitRotation({
        ancestorIpnsNames: [folderIpnsName],
        rootNodeIpnsName: folderIpnsName,
        rootNodeId: folder.nodeId,
        rootReadKey: folder.folderKey,
        rootIpnsPrivateKey: folder.ipnsKeypair.privateKey,
        rootIpnsPublicKey: folder.ipnsKeypair.publicKey,
      });

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
        children: targetState
          ? await this.resolveListingChildren(
              targetState.children,
              targetState.folderKey,
              targetFolderIpnsName,
              targetState.sequenceNumber
            )
          : [],
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
   * addToIpfsFn: uploads encrypted content via pinWithMode so the configured
   * pinning mode (BYO/external) is honored — encrypted bytes never route through
   * CipherBox when the user opted external. Returns the resulting CID.
   *
   * publishNodeFn: uploads the sealed PublishedNode JSON to IPFS then calls
   * createAndPublishIpnsRecord with the supplied sequenceNumber (callers in
   * shared-write.ts supply the target new sequence directly). The node-metadata
   * blob intentionally goes via sdkCore.addToIpfs (CipherBox), NOT pinWithMode:
   * it is the IPNS resolution target and must remain reachable by CipherBox's
   * relay — mirrors the non-shared metadata-publish path. Returns the new
   * sequence number echoed from the API response.
   */
  private buildSharedWriteContextFromState(
    state: SharedFolderState
  ): ReturnType<typeof shareOps.buildSharedWriteContext> {
    return this.buildSharedWriteContextWithOverrides(state, {
      readKey: state.folderKey,
      writeKey: state.writeKey,
      publishedNode: state.publishedNode,
      ipnsName: state.ipnsName,
      sequenceNumber: state.sequenceNumber,
      children: state.children,
    });
  }

  /**
   * Build a SharedWriteContext for an ARBITRARY folder (readKey/writeKey/
   * publishedNode/ipnsName/sequenceNumber/children explicitly supplied),
   * reusing `owningState`'s per-share owner/recipient pubkeys, shareId, and
   * `addShareKeysFn` callback (share-scoped, not folder-scoped — no
   * cross-share bleed, T-48-07). Used by {@link buildSharedWriteContextFromState}
   * for the currently-loaded folder AND by `moveInSharedFolder` to build a
   * one-off destination context from a freshly-resolved (never cached, A1)
   * destination folder that is NOT itself tracked in `sharedFolderTree`.
   *
   * addToIpfsFn / publishNodeFn seams match `buildSharedWriteContextFromState`
   * exactly (BYO-aware content pinning; node metadata always via CipherBox).
   */
  private buildSharedWriteContextWithOverrides(
    owningState: SharedFolderState,
    overrides: {
      readKey: Uint8Array;
      writeKey: Uint8Array;
      publishedNode: PublishedNode;
      ipnsName: string;
      sequenceNumber: bigint;
      children: SealedChildRef[];
    }
  ): ReturnType<typeof shareOps.buildSharedWriteContext> {
    const { addToIpfsFn, publishNodeFn } = this.buildWriteTransportSeams();
    return shareOps.buildSharedWriteContext({
      ctx: this.ctx,
      readKey: overrides.readKey,
      writeKey: overrides.writeKey,
      publishedNode: overrides.publishedNode,
      ipnsName: overrides.ipnsName,
      sequenceNumber: overrides.sequenceNumber,
      children: overrides.children,
      ownerPublicKey: owningState.ownerPublicKey,
      recipientPublicKey: owningState.recipientPublicKey,
      shareId: owningState.shareId,
      addToIpfsFn,
      publishNodeFn,
      addShareKeysFn: owningState.addShareKeysFn,
    });
  }

  /**
   * Build the transport seams (addToIpfsFn + publishNodeFn) shared by every
   * SharedWriteContext builder (68.1-32). Extracted so
   * {@link buildSharedWriteContextWithOverrides} and the single-file-share
   * write path ({@link updateSharedSingleFile}, which has no owning
   * `SharedFolderState` to build a context FROM) don't duplicate the transport
   * wiring — behavior is byte-for-byte identical to the pre-extraction inline
   * implementation.
   *
   * addToIpfsFn: uploads encrypted content via pinWithMode so the configured
   * pinning mode (BYO/external) is honored — encrypted bytes never route
   * through CipherBox when the user opted external.
   *
   * publishNodeFn: uploads the sealed PublishedNode JSON to IPFS then calls
   * createAndPublishIpnsRecord with the supplied sequenceNumber. The
   * node-metadata blob intentionally goes via sdkCore.addToIpfs (CipherBox),
   * NOT pinWithMode — it is the IPNS resolution target and must remain
   * reachable by CipherBox's relay. A non-throwing rejection (2xx with
   * success:false) still means the record was not committed — fail closed
   * rather than pointing a SealedChildRef/IPNS name at an unpublished record.
   */
  private buildWriteTransportSeams(): {
    addToIpfsFn: (data: Uint8Array) => Promise<{ cid: string }>;
    publishNodeFn: (params: {
      published: PublishedNode;
      ipnsName: string;
      ipnsPrivateKey: Uint8Array;
      sequenceNumber: bigint;
    }) => Promise<{ tombstoned: true } | { tombstoned: false; newSequenceNumber: bigint }>;
  } {
    return {
      addToIpfsFn: async (data) => {
        const result = await this.pinWithMode(data, this.ctx);
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
        if (!pubResult.success) {
          throw new Error(
            `publishNodeFn: IPNS publish rejected for ${ipnsName} (seq=${pubResult.sequenceNumber})`
          );
        }
        return { tombstoned: false, newSequenceNumber: pubResult.sequenceNumber };
      },
    };
  }

  /**
   * Adopt a shared-write result into `sharedFolderTree` and emit
   * `sharedFolder:updated`. Centralizes the write-back + emission so all five
   * methods stay consistent.
   */
  private async adoptSharedFolderResult(
    shareId: string,
    result: {
      publishedChildren: SealedChildRef[];
      newSequenceNumber: bigint;
      publishedParent?: PublishedNode;
    }
  ): Promise<void> {
    // Re-read live state: the share may have been unloaded (e.g. unmount →
    // unloadSharedFolder) while the async write/refresh was in-flight. Never
    // resurrect an explicitly-unloaded share from a pre-await snapshot.
    const live = this.sharedFolderTree.get(shareId);
    if (!live) return;
    const next: SharedFolderState = {
      ...live,
      children: result.publishedChildren,
      sequenceNumber: result.newSequenceNumber,
      // 68.1-29: adopt the freshly-published envelope when the op returns it —
      // a later same-session shared write unsealing a STALE publishedNode
      // republishes an outdated write chain, silently dropping WriteChildRefs
      // inserted by earlier ops (writable-shares 3.3 mkdir dropped 3.2's
      // upload write-link, breaking the 3.4 editor save).
      ...(result.publishedParent ? { publishedNode: result.publishedParent } : {}),
    };
    this.sharedFolderTree.set(shareId, next);
    this.emitter.emit({
      type: 'sharedFolder:updated',
      shareId,
      ipnsName: live.ipnsName,
      children: await this.resolveListingChildren(
        result.publishedChildren,
        next.folderKey,
        live.ipnsName,
        result.newSequenceNumber
      ),
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
      await this.adoptSharedFolderResult(shareId, result);
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
      await this.adoptSharedFolderResult(shareId, result);
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
      await this.adoptSharedFolderResult(shareId, result);
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
      await this.adoptSharedFolderResult(shareId, result);
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
      filePointer: SealedChildRef;
      newContent: Uint8Array;
      getFileIpnsKeyFn: (itemId: string) => Promise<Uint8Array | null>;
    }
  ): Promise<void> {
    return this.withOperation('updateSharedFile', async () => {
      const state = this.requireSharedFolder(shareId);
      const swCtx = this.buildSharedWriteContextFromState(state);

      // Unseal the parent's write-body so the file's WriteChildRef (keyed by
      // UUID) can be walked (mirrors shared-write.ts unsealParentWriteBody).
      //
      // 68.1-29: resolve the parent's CURRENT on-wire record instead of
      // trusting state.publishedNode — adoptSharedFolderResult adopts
      // children/sequence after a shared write but NOT the envelope, so a
      // file uploaded THIS session has no WriteChildRef in the stale
      // envelope and the save failed with "cannot resolve write
      // key/ipnsPrivateKey" (writable-shares 3.4). The fresh envelope is
      // adopted back into state so later ops see it too.
      const parentResolved = await this.resolvePublishedNode(state.ipnsName);
      const parentPublished = parentResolved?.published ?? state.publishedNode;
      if (parentResolved) {
        this.sharedFolderTree.set(shareId, { ...state, publishedNode: parentResolved.published });
      }
      const parentNode = await unsealNode(parentPublished, state.folderKey, state.writeKey);
      if (!parentNode.writeBody) {
        throw new Error('updateSharedFile: shared folder has no write-body — not write-capable');
      }

      // Resolve the file's own PublishedNode envelope — id/kind are plaintext
      // (NODE-03) and are the AAD inputs for unsealChildReadKey/unsealChildWriteKey.
      const filePub = await this.resolvePublishedNode(args.filePointer.ipnsName);
      if (!filePub) {
        throw new Error(`updateSharedFile: cannot resolve file IPNS ${args.filePointer.ipnsName}`);
      }
      const fileNodeId = filePub.published.id;
      const fileKind = filePub.published.kind;

      // Recover the file's readKey from the parent read-body.
      let fileReadKey: Uint8Array | null = await unsealChildReadKey(
        args.filePointer.readKeySealed,
        state.folderKey,
        fileNodeId,
        fileKind,
        args.filePointer.generation
      );
      let fileWriteKey: Uint8Array | null = null;
      let fileIpnsPrivateKey: Uint8Array | null = null;
      // Hoisted so the finally can zero its decrypted content key (D-09).
      let currentFileNode: CoreNode | null = null;

      try {
        // Walk the parent write-body: find the WriteChildRef for this file (matched
        // by UUID, never ipnsName), then recover the file's writeKey and, from the
        // file's own write-body, its ipnsPrivateKey (shared-write.ts walkChildWriteKey
        // + unsealParentWriteBody pattern, inlined here since both helpers are
        // module-private to shared-write.ts).
        const writeChildRef = parentNode.writeBody.writeChildren.find(
          (wc) => wc.childId === fileNodeId
        );
        if (writeChildRef) {
          fileWriteKey = await unsealChildWriteKey(
            writeChildRef.writeKeySealed,
            state.writeKey,
            fileNodeId,
            fileKind,
            args.filePointer.generation
          );
          currentFileNode = await unsealNode(filePub.published, fileReadKey, fileWriteKey);
          fileIpnsPrivateKey = currentFileNode.writeBody?.ipnsPrivateKey ?? null;
        }

        // Share-key fallback (legacy path, kept per the existing signature): no
        // write link was recorded for this file — fall back to the caller-supplied
        // lookup for the ipnsPrivateKey. A missing writeKey still fails closed below
        // (a write-body republish is impossible without one).
        if (!fileIpnsPrivateKey) {
          fileIpnsPrivateKey = await args.getFileIpnsKeyFn(args.filePointer.ipnsName);
        }
        if (!fileWriteKey || !fileIpnsPrivateKey) {
          throw new Error(
            `updateSharedFile: cannot resolve write key/ipnsPrivateKey for file ${args.filePointer.ipnsName}`
          );
        }
        if (!currentFileNode || currentFileNode.kind !== 'file' || !currentFileNode.content) {
          throw new Error(`updateSharedFile: node ${args.filePointer.ipnsName} is not a file node`);
        }

        await shareOps.updateSharedFile(swCtx, {
          fileRef: args.filePointer,
          fileNodeId,
          fileReadKey,
          fileWriteKey,
          fileIpnsPrivateKey,
          fileSequenceNumber: filePub.sequenceNumber,
          newData: args.newContent,
          originalCreatedAt: currentFileNode.createdAt,
          originalVersions: currentFileNode.content.versions,
        });

        // File-only publish: the parent's children/sequence are unchanged — emit
        // sharedFolder:updated with the current live snapshot so consumers
        // re-resolve the file (mirrors refreshSharedFolder's file-only emission).
        //
        // 68.2-02 (Rule 1 fix): the parent folder's OWN ipnsName+sequenceNumber
        // is unchanged by a file-only content publish, but the just-updated
        // FILE's own PublishedNode (content/modifiedAt) is now stale in
        // `listingCache` if it was resolved before this update. Invalidate
        // the parent's cache entry so the emitted ResolvedChild[] re-resolves
        // every child (including the just-updated file) instead of serving a
        // stale cached size/modifiedAt for it.
        const live = this.sharedFolderTree.get(shareId);
        if (live) {
          this.listingCache.delete(live.ipnsName);
          this.emitter.emit({
            type: 'sharedFolder:updated',
            shareId,
            ipnsName: live.ipnsName,
            children: await this.resolveListingChildren(
              live.children,
              live.folderKey,
              live.ipnsName,
              live.sequenceNumber
            ),
            sequenceNumber: live.sequenceNumber,
          });
        }
      } finally {
        // Zero all derived (never caller-owned) file keys on every exit path (D-09).
        fileReadKey?.fill(0);
        fileReadKey = null;
        fileWriteKey?.fill(0);
        fileWriteKey = null;
        fileIpnsPrivateKey?.fill(0);
        fileIpnsPrivateKey = null;
        // Zero the decrypted content key too — never handed to the caller.
        currentFileNode?.content?.fileKey?.fill(0);
      }
    });
  }

  /**
   * Update a DIRECT single-file share's content (WEB-03, writable-shares 10.3).
   *
   * A single-file share's root IS the file — there is no parent folder write
   * chain to walk (unlike {@link updateSharedFile}'s folder path, which
   * requires a loaded `SharedFolderState`). The file's readKey/writeKey are
   * recovered directly from the grant's ECIES-wrapped encrypted keys
   * (`share.encryptedReadKey`/`share.encryptedWriteKey`), and the file's
   * ipnsPrivateKey is recovered by unsealing the file's own write-body
   * (validate-before-trust — a wrong/tampered encrypted key fails AEAD auth
   * closed here, never caught-and-continued).
   *
   * Publishes to the file's OWN IPNS at the resolved sequence + 1 via the
   * same transport seams as every other shared-write path
   * ({@link buildWriteTransportSeams}: BYO-aware content pin, CipherBox-relayed
   * node metadata, fail-closed on publish rejection).
   */
  async updateSharedSingleFile(args: {
    shareId: string;
    encryptedReadKey: string;
    encryptedWriteKey: string;
    fileIpnsName: string;
    ownerPublicKey: Uint8Array;
    /** Caller-owned — NEVER zeroed by this method (D-09). */
    recipientPrivateKey: Uint8Array;
    recipientPublicKey: Uint8Array;
    rootExpectedGeneration: number;
    newContent: Uint8Array;
  }): Promise<void> {
    return this.withOperation('updateSharedSingleFile', async () => {
      // Recovered file keys — MINTED by this call, terminal owner (D-09).
      // args.recipientPrivateKey is caller-owned and is NEVER zeroed here.
      let fileReadKey: Uint8Array | null = await unwrapKey(
        hexToBytes(args.encryptedReadKey),
        args.recipientPrivateKey
      );
      let fileWriteKey: Uint8Array | null = await unwrapKey(
        hexToBytes(args.encryptedWriteKey),
        args.recipientPrivateKey
      );
      let currentFileNode: CoreNode | null = null;

      try {
        const filePub = await this.resolvePublishedNode(args.fileIpnsName);
        if (!filePub) {
          throw new Error(`updateSharedSingleFile: file ${args.fileIpnsName} not found (revoked)`);
        }

        // Behind-retry staleness witness — never trust a generation regression,
        // mirrors navigateReadChain's behind-retry semantics.
        if (filePub.published.generation > args.rootExpectedGeneration) {
          throw new Error('updateSharedSingleFile: share was updated — please reopen');
        }

        // Validate-before-trust for BOTH keys: a wrong/tampered encrypted key
        // fails AEAD auth closed here (T-68.1-32-01) — never caught.
        currentFileNode = await unsealNode(filePub.published, fileReadKey, fileWriteKey);

        if (
          currentFileNode.kind !== 'file' ||
          !currentFileNode.content ||
          !currentFileNode.writeBody?.ipnsPrivateKey
        ) {
          throw new Error(
            `updateSharedSingleFile: node ${args.fileIpnsName} is not a writable file node`
          );
        }
        const fileIpnsPrivateKey = currentFileNode.writeBody.ipnsPrivateKey;

        const { addToIpfsFn, publishNodeFn } = this.buildWriteTransportSeams();
        const swCtx = shareOps.buildSharedWriteContext({
          ctx: this.ctx,
          readKey: fileReadKey,
          writeKey: fileWriteKey,
          publishedNode: filePub.published,
          ipnsName: args.fileIpnsName,
          sequenceNumber: filePub.sequenceNumber,
          children: [],
          ownerPublicKey: args.ownerPublicKey,
          recipientPublicKey: args.recipientPublicKey,
          shareId: args.shareId,
          addToIpfsFn,
          publishNodeFn,
          // D-02: never invoked in the write-body model.
          addShareKeysFn: async () => {},
        });

        await shareOps.updateSharedFile(swCtx, {
          fileRef: {
            name: '',
            ipnsName: args.fileIpnsName,
            generation: filePub.published.generation,
            versionFloor: 0n,
            readKeySealed: '',
          },
          fileNodeId: filePub.published.id,
          fileReadKey,
          fileWriteKey,
          fileIpnsPrivateKey,
          fileSequenceNumber: filePub.sequenceNumber,
          newData: args.newContent,
          mimeType: currentFileNode.content.mimeType,
          originalCreatedAt: currentFileNode.createdAt,
          originalVersions: currentFileNode.content.versions,
        });
      } finally {
        // Zero every minted/unsealed key on every exit path (D-09 terminal owner).
        fileReadKey?.fill(0);
        fileReadKey = null;
        fileWriteKey?.fill(0);
        fileWriteKey = null;
        currentFileNode?.writeBody?.ipnsPrivateKey?.fill(0);
        currentFileNode?.content?.fileKey?.fill(0);
      }
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
          children: await this.resolveListingChildren(
            live.children,
            live.folderKey,
            live.ipnsName,
            live.sequenceNumber
          ),
          sequenceNumber: live.sequenceNumber,
        });
        return;
      }

      await this.adoptSharedFolderResult(shareId, {
        publishedChildren: result.metadata.children ?? [],
        newSequenceNumber: result.sequenceNumber,
      });
    });
  }

  /**
   * Move an item between two subfolders within a single shared folder (REQ-2).
   *
   * Resolves the destination folder's read/write keys from the shared
   * write-chain seeded in `sharedFolderTree` (68.1-20): unseals the SOURCE
   * folder's own write-body (its `writeKey` was seeded at navigation time —
   * root depth only, see `useSharedNavigationActions.ts` navigateToShare),
   * looks up the destination's `WriteChildRef` by UUID, and derives
   * `destWriteKey` via `unsealChildWriteKey`. `destFolderKey` (readKey) is
   * derived the same way the moved item's own readKey always was — via the
   * destination's `SealedChildRef.readKeySealed` in the source folder's
   * read-body children. `destIpnsPrivateKey` comes from unsealing the
   * destination's own node under its now-recovered read+write keys.
   *
   * `getShareKeysFn` is retained for backward compatibility: a non-empty
   * result (a caller supplying a real per-child share_keys fan-out) is still
   * honored via the legacy path below. Every current web caller's
   * `fetchShareKeys` now always returns `[]` (68.1-20 Task 1 — no live
   * share_keys endpoint exists), which routes here to the write-chain path.
   *
   * KNOWN BLOCKER (documented per 68.1-20 Task 3, not silently worked around):
   * this resolves the destination ONLY when it is a direct child of the
   * CURRENTLY ACTIVE shared folder's own write-body — i.e., `srcState` IS the
   * destination's immediate parent. There is no general write-tree DFS
   * primitive (the read-chain has `enumerateSharedSubtree`'s share_keys-based
   * walk, itself now also broken by the same share_keys removal — a
   * pre-existing, separately-tracked gap, not introduced here). A move whose
   * destination is NOT a direct sibling of the moved item's own parent throws
   * a clear, fail-closed error rather than guessing or falling back to a zero
   * key — deeper multi-hop write-chain resolution is out of this plan's scope
   * and needs a dedicated follow-up (a write-body equivalent of
   * `enumerateSharedSubtree`).
   *
   * Publishes DEST first → re-key → publish SOURCE (dup-not-orphan,
   * T-68.1-08-04). Adopts the SOURCE result into `sharedFolderTree` and emits
   * `sharedFolder:updated` for the active depth (source) — the dest result is
   * never adopted (it is not the currently-loaded state for this share,
   * Pitfall 1).
   *
   * Key zeroing (T-49-04/T-68.1-08-02): all locally-derived `destFolderKey` /
   * `destWriteKey` / `destIpnsPrivateKey` and the derived `childReadKey` are
   * zeroed in `finally`. `vaultPrivateKey` is caller-owned and never zeroed
   * here (D-09).
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
    return this.withOperation('moveInSharedFolder', async () => {
      const srcState = this.requireSharedFolder(shareId);

      // Defense-in-depth: a folder cannot be moved into itself (would
      // orphan/cycle the subtree). The picker (enumerateSharedSubtree) already
      // excludes a moved folder's own subtree from selection.
      if (args.destFolderId === args.itemId) {
        throw new Error('Cannot move a folder into itself');
      }

      const shareKeys = await args.getShareKeysFn(shareId);

      let destFolderKey: Uint8Array | null = null;
      let destWriteKey: Uint8Array | null = null;
      let destIpnsPrivateKey: Uint8Array | null = null;
      let destPublished: PublishedNode;
      let destSequenceNumber: bigint;
      let destChildren: SealedChildRef[];

      try {
        if (shareKeys.length > 0) {
          // Legacy path (kept for compatibility, T-49-01/T-68.1-08-01
          // write-capability guard): a caller supplying a real per-child
          // share_keys fan-out is still honored — fail closed before any
          // publish or key unwrap if either entry is missing.
          const destFolderKeyRecord = shareKeys.find(
            (k) => k.keyType === 'folder' && k.itemId === args.destFolderId
          );
          if (!destFolderKeyRecord) throw new Error('No read key for destination folder');

          const destFolderIpnsRecord = shareKeys.find(
            (k) => k.keyType === 'folder-ipns' && k.itemId === args.destFolderId
          );
          if (!destFolderIpnsRecord) throw new Error('No write key for destination folder');

          destFolderKey = await unwrapKey(
            hexToBytes(destFolderKeyRecord.encryptedKey),
            args.vaultPrivateKey
          );
          destIpnsPrivateKey = await unwrapKey(
            hexToBytes(destFolderIpnsRecord.encryptedKey),
            args.vaultPrivateKey
          );

          // Load dest children fresh — never a cached/stale ref (A1).
          const destMeta = await sdkCore.loadFolderMetadata({
            ipnsName: args.destIpnsName,
            folderKey: destFolderKey,
            ctx: this.ctx,
          });
          if (!destMeta) {
            throw new Error(
              `moveInSharedFolder: cannot resolve destination folder ${args.destIpnsName}`
            );
          }
          // Reuse the CID loadFolderMetadata already resolved instead of a
          // second IPNS resolve round trip — content-addressed, same bytes.
          const destRaw = await sdkCore.fetchFromIpfs(this.ctx, destMeta.cid);
          destPublished = JSON.parse(new TextDecoder().decode(destRaw)) as PublishedNode;
          destSequenceNumber = destMeta.sequenceNumber;
          destChildren = destMeta.metadata.children ?? [];
          // No write-body write-chain key in the legacy path — the
          // folder-ipns share_keys entry plugs directly into writeKey below.
          destWriteKey = destIpnsPrivateKey;
        } else {
          // 68.1-20: write-chain resolution — no live share_keys fan-out
          // exists (fetchShareKeys always returns [], Task 1). Unseal the
          // SOURCE folder's own write-body under its seeded writeKey and walk
          // one hop to the destination's WriteChildRef.
          const srcParentNode = await unsealNode(
            srcState.publishedNode,
            srcState.folderKey,
            srcState.writeKey
          );
          if (!srcParentNode.writeBody) {
            throw new Error(
              'moveInSharedFolder: source folder has no write-body -- not write-capable ' +
                '(writeKey unseeded or zero; only the share ROOT depth is seeded with a real ' +
                'writeKey today, see useSharedNavigationActions.ts navigateToShare)'
            );
          }

          const destPub = await this.resolvePublishedNode(args.destIpnsName);
          if (!destPub) {
            throw new Error(
              `moveInSharedFolder: cannot resolve destination IPNS ${args.destIpnsName}`
            );
          }
          const destNodeId = destPub.published.id;
          const destKind = destPub.published.kind;

          const destWriteChildRef = srcParentNode.writeBody.writeChildren.find(
            (wc) => wc.childId === destNodeId
          );
          // destReadRef supplies the parent-mirror generation (write-chain
          // AADs use the SAME generation source as the read-chain, §2.6) and
          // the destination's readKeySealed.
          const destReadRef = srcState.children.find((c) => c.ipnsName === args.destIpnsName);

          if (!destWriteChildRef || !destReadRef) {
            // KNOWN BLOCKER (see method doc): destination is not a direct
            // child of the currently active shared folder's write-body. Fail
            // closed with a precise, actionable error rather than a
            // zero/guessed key.
            throw new Error(
              `moveInSharedFolder: destination ${args.destIpnsName} is not a direct child of ` +
                "the currently active shared folder's write-chain -- cross-subtree write-chain " +
                'resolution beyond one hop is not implemented (68.1-20 known blocker). ' +
                'Navigate so the destination is a direct child of the folder you are moving from.'
            );
          }

          destFolderKey = await unsealChildReadKey(
            destReadRef.readKeySealed,
            srcState.folderKey,
            destNodeId,
            destKind,
            destReadRef.generation
          );
          destWriteKey = await unsealChildWriteKey(
            destWriteChildRef.writeKeySealed,
            srcState.writeKey,
            destNodeId,
            destKind,
            destReadRef.generation
          );

          const destNode = await unsealNode(destPub.published, destFolderKey, destWriteKey);
          destIpnsPrivateKey = destNode.writeBody?.ipnsPrivateKey ?? null;
          if (!destIpnsPrivateKey) {
            throw new Error(
              `moveInSharedFolder: destination ${args.destIpnsName} write-body has no ipnsPrivateKey`
            );
          }

          destPublished = destPub.published;
          destSequenceNumber = destPub.sequenceNumber;
          destChildren = destNode.children ?? [];
        }

        // Resolve the moved child's UUID/kind (plaintext on its own PublishedNode
        // envelope, NODE-03) + readKey (unsealed through the SOURCE folderKey).
        const movedRef = srcState.children.find((c) => c.ipnsName === args.itemId);
        if (!movedRef) {
          throw new Error(`moveInSharedFolder: item not found in source: ${args.itemId}`);
        }
        const itemPub = await this.resolvePublishedNode(args.itemId);
        if (!itemPub) {
          throw new Error(`moveInSharedFolder: cannot resolve item IPNS ${args.itemId}`);
        }
        const childNodeId = itemPub.published.id;
        const childKind = itemPub.published.kind;
        const childGeneration = movedRef.generation;

        let childReadKey: Uint8Array | null = await unsealChildReadKey(
          movedRef.readKeySealed,
          srcState.folderKey,
          childNodeId,
          childKind,
          childGeneration
        );

        try {
          const srcCtx = this.buildSharedWriteContextFromState(srcState);
          const destCtx = this.buildSharedWriteContextWithOverrides(srcState, {
            readKey: destFolderKey,
            writeKey: destWriteKey,
            publishedNode: destPublished,
            ipnsName: args.destIpnsName,
            sequenceNumber: destSequenceNumber,
            children: destChildren,
          });

          const { srcResult } = await shareOps.moveInSharedFolder({
            srcCtx,
            destCtx,
            itemId: args.itemId,
            childNodeId,
            childKind,
            childGeneration,
            childReadKey,
          });

          // Adopt SOURCE only — the destination is not this share's active
          // depth (Pitfall 1); its own subtree view (if open) re-resolves via
          // its own navigation/enumerateSharedSubtree call.
          await this.adoptSharedFolderResult(shareId, srcResult);
        } finally {
          childReadKey?.fill(0);
          childReadKey = null;
        }
      } finally {
        // Zero all temporarily-resolved dest key material (T-49-04/T-68.1-08-02).
        // vaultPrivateKey is caller-owned — never zeroed here (D-09).
        destIpnsPrivateKey?.fill(0);
        destIpnsPrivateKey = null;
        destWriteKey?.fill(0);
        destWriteKey = null;
        destFolderKey?.fill(0);
        destFolderKey = null;
      }
    });
  }

  /**
   * Enumerate all reachable subfolders within a shared folder tree (DFS),
   * walking the node/v3 read/write chain from the loaded `SharedFolderState`
   * (closes GAP-7 — the deleted `share_keys` table is never consulted).
   *
   * Read-chain descent: each `SealedChildRef.readKeySealed` is unsealed with
   * the PARENT's readKey via `unsealChildReadKey`, using the parent-mirror
   * generation (childRef.generation), never the child's own envelope
   * generation (§2.6, matching `dfsFindFolder`/`navigateReadChain`). A
   * structurally-unresolvable hop (missing IPNS record) is a soft skip; an
   * AEAD auth failure on a present-but-wrong body throws (fail-closed).
   *
   * Write-chain descent: a node is `writable: true` only when a
   * `WriteChildRef` for its id exists in the PARENT's unsealed write-body AND
   * `unsealChildWriteKey` succeeds under the parent writeKey. A read-only
   * child (no WriteChildRef) is still listed (`writable: false`) and its own
   * children are still enumerated via the read chain, but no write-chain
   * lookup is attempted for its descendants — writability never re-appears
   * below a read-only node.
   *
   * D-09 zeroization: every locally-minted childReadKey/childWriteKey is
   * zeroed in a `finally` after it is consumed (used to unseal the child Node
   * + recurse). `state.folderKey`/`state.writeKey` (sharedFolderTree-owned)
   * are never zeroed here.
   *
   * @param shareId - Share ID seeded via loadSharedFolder
   * @returns Flat list of reachable subfolders with writable flag and parentId
   */
  async enumerateSharedSubtree(shareId: string): Promise<
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

      const hasRealWriteKey = (wk: Uint8Array | null | undefined): boolean =>
        !!wk && wk.length === 32 && !wk.every((b) => b === 0);

      // Unseal the share root's OWN write-body once (if it is write-capable)
      // so the first DFS level has a writeChildren list to check children
      // against — mirrors dfsFindFolder's parentNode.writeBody lookup.
      let rootWriteChildren: WriteChildRef[] = [];
      if (hasRealWriteKey(state.writeKey)) {
        const rootNode = await unsealNode(state.publishedNode, state.folderKey, state.writeKey);
        rootWriteChildren = rootNode.writeBody?.writeChildren ?? [];
      }

      const result: Array<{
        id: string;
        name: string;
        ipnsName: string;
        writable: boolean;
        parentId: string | null;
      }> = [];

      // Visited guard prevents infinite loops on cyclic ipnsName references.
      const visited = new Set<string>();

      const walk = async (
        children: SealedChildRef[],
        parentReadKey: Uint8Array,
        parentWriteKey: Uint8Array | null,
        parentWriteChildren: WriteChildRef[],
        parentId: string | null
      ): Promise<void> => {
        for (const child of children) {
          if (visited.has(child.ipnsName)) continue;

          const childResolved = await this.resolvePublishedNode(child.ipnsName);
          if (!childResolved) continue; // structurally unresolvable hop -- try siblings

          visited.add(child.ipnsName);

          let childReadKey: Uint8Array | null = null;
          let childWriteKey: Uint8Array | null = null;
          try {
            // Generation-source rule: child.generation (parent mirror), NEVER
            // childResolved.published.generation (child's own envelope).
            childReadKey = await unsealChildReadKey(
              child.readKeySealed,
              parentReadKey,
              childResolved.published.id,
              childResolved.published.kind,
              child.generation
            );

            // A file leaf is never a move destination -- only folder/root
            // kinds are listed and descended into.
            if (
              childResolved.published.kind !== 'folder' &&
              childResolved.published.kind !== 'root'
            ) {
              continue;
            }

            const writeChildRef = parentWriteChildren.find(
              (wc) => wc.childId === childResolved.published.id
            );

            let writable = false;
            if (writeChildRef && parentWriteKey) {
              childWriteKey = await unsealChildWriteKey(
                writeChildRef.writeKeySealed,
                parentWriteKey,
                childResolved.published.id,
                childResolved.published.kind,
                child.generation
              );
              writable = true;
            }

            result.push({
              id: child.ipnsName,
              name: child.name,
              ipnsName: child.ipnsName,
              writable,
              parentId,
            });

            const childNode = await unsealNode(
              childResolved.published,
              childReadKey,
              childWriteKey ?? undefined
            );

            if (childNode.children && childNode.children.length > 0) {
              await walk(
                childNode.children,
                childReadKey,
                writable ? childWriteKey : null,
                writable ? (childNode.writeBody?.writeChildren ?? []) : [],
                child.ipnsName
              );
            }
          } finally {
            childReadKey?.fill(0);
            childWriteKey?.fill(0);
          }
        }
      };

      await walk(
        state.children,
        state.folderKey,
        hasRealWriteKey(state.writeKey) ? state.writeKey : null,
        rootWriteChildren,
        null
      );

      return result;
    });
  }

  /**
   * Recover a single subfolder's writeKey from its PARENT's write-body chain
   * (one hop), closing the deep-shared-write gap (WEB-03, 68.1-30): the web
   * seeds `SharedFolderState.writeKey` only at the share root
   * (`resolveSharedRootWriteKey`), so descending into a subfolder previously
   * re-seeded that depth with a zero writeKey and every write op below the
   * root failed GCM auth (writable-shares 8.2).
   *
   * Mirrors `dfsFindFolder`'s inner write-chain block exactly: the caller
   * (`navigateToSubfolder`) must invoke this BEFORE it re-seeds
   * `sharedFolderTree` to the child — this method reads the PARENT depth via
   * `sharedFolderTree.get(shareId)`.
   *
   * Generation-source rule: `child.generation` is the PARENT-mirror
   * (`SealedChildRef.generation`), NEVER `child.published.generation` (the
   * child's own envelope generation) — matches `dfsFindFolder` /
   * `enumerateSharedSubtree`.
   *
   * Fails closed: returns `null` when the share isn't loaded, the parent has
   * no real (non-zero 32-byte) writeKey, the parent has no write-body, or no
   * `WriteChildRef` matches the child's id. A tampered `writeKeySealed` or
   * wrong parent writeKey throws (AEAD auth failure) rather than being
   * swallowed. The recovered key is validated by unsealing the child's OWN
   * write-body before being trusted/returned — a key that doesn't unseal the
   * child's write-body returns `null`, never a bogus key.
   *
   * D-09 zeroization: the local `childWriteKey` is zeroed in a `finally`
   * after being consumed for validation. The returned buffer is a fresh copy
   * the caller becomes the terminal owner of. `parent.writeKey`/
   * `parent.folderKey`/`child.readKey` (caller/tree-owned) are never zeroed
   * here.
   *
   * @param shareId - Share ID seeded via loadSharedFolder (must be the
   *   PARENT depth, not yet re-seeded to the child)
   * @param child - The subfolder to recover a writeKey for: its resolved
   *   `PublishedNode`, its already-unsealed `readKey`, and the PARENT-mirror
   *   `generation` (`SealedChildRef.generation`)
   * @returns The child's raw 32-byte writeKey (fresh copy), or `null` when
   *   the parent/child are not write-linked or the parent is read-only
   */
  async resolveSharedSubfolderWriteKey(
    shareId: string,
    child: { published: PublishedNode; readKey: Uint8Array; generation: number }
  ): Promise<Uint8Array | null> {
    return this.withOperation('resolveSharedSubfolderWriteKey', async () => {
      const parent = this.sharedFolderTree.get(shareId);
      if (!parent) return null;

      const hasRealWriteKey =
        parent.writeKey.length === 32 && !parent.writeKey.every((b) => b === 0);
      if (!hasRealWriteKey) return null;

      const parentNode = await unsealNode(parent.publishedNode, parent.folderKey, parent.writeKey);
      if (!parentNode.writeBody) return null;

      const writeChildRef = parentNode.writeBody.writeChildren.find(
        (wc) => wc.childId === child.published.id
      );
      if (!writeChildRef) return null;

      let childWriteKey: Uint8Array | null = null;
      try {
        childWriteKey = await unsealChildWriteKey(
          writeChildRef.writeKeySealed,
          parent.writeKey,
          child.published.id,
          child.published.kind,
          child.generation
        );

        // T-68.1-30-02: validate before trust (fail-closed, NOT caught) —
        // mirrors dfsFindFolder's T-68.1-01-03 guarantee.
        const childNode = await unsealNode(child.published, child.readKey, childWriteKey);
        if (!childNode.writeBody) return null;

        return new Uint8Array(childWriteKey);
      } finally {
        childWriteKey?.fill(0);
      }
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
