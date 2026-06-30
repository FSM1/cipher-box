/**
 * @cipherbox/sdk - Type definitions
 *
 * Client configuration and internal state types for the SDK.
 * These types define the contract between the SDK and its consumers.
 */

import type { TeeKeys, PinningMode, ExternalProviderConfig } from '@cipherbox/sdk-core';
import type { AxiosInstance } from '@cipherbox/api-client';
import type { SealedChildRef, Node, PublishedNode } from '@cipherbox/core';
import type { SentShareInfo, ShareKeyType } from './share';

/**
 * Pinning configuration for BYO-IPFS support.
 * When absent, defaults to cipherbox-only mode.
 */
export type PinningConfig = {
  mode: PinningMode;
  externalProvider?: ExternalProviderConfig;
};

/**
 * Callbacks for share-aware key re-wrapping.
 *
 * The SDK uses these to discover active shares and store re-wrapped keys
 * without taking a direct dependency on the shares API or stores.
 */
export type ShareCallbacks = {
  /** Find active shares covering a folder (including ancestor shares). */
  getCoveringShares: (folderIpnsName: string) => Promise<SentShareInfo[]>;
  /** Store re-wrapped keys for a share via the API. */
  addShareKeys: (
    shareId: string,
    keys: Array<{ keyType: 'file' | 'folder'; itemId: string; encryptedKey: string }>
  ) => Promise<void>;
};

/**
 * Configuration for initializing a CipherBoxClient instance.
 *
 * Consumers provide authentication, keypair, and root folder details.
 * The SDK manages everything else internally.
 */
export type CipherBoxClientConfig = {
  /** Base URL for the CipherBox API (e.g., "https://api.cipherbox.cc") */
  apiUrl: string;
  /** Returns a valid access token. Consumer owns refresh logic. */
  getAccessToken: () => Promise<string>;
  /** User's vault keypair (secp256k1). Used for ECIES operations. */
  vaultKeypair: { publicKey: Uint8Array; privateKey: Uint8Array };
  /** Root folder IPNS name (k51.../bafzaa...) */
  rootIpnsName: string;
  /** Root folder key (AES-256, decrypted on login) */
  rootFolderKey: Uint8Array;
  /**
   * Root folder IPNS signing keypair (Ed25519).
   *
   * When provided, the client can self-bootstrap and lazy-load the folder tree
   * from root on its own (see `CipherBoxClient.ensureFolderLoaded`): it resolves
   * the root folder, then walks down to any target by unwrapping each subfolder's
   * keys with the vault keypair. This dissolves the "Folder not loaded" failure
   * class — consumers no longer need to pre-seed `folderTree` before every
   * folderTree-dependent operation (e.g. bin restore after a reload).
   *
   * Optional for backward compatibility: when absent, folders must be registered
   * externally via `registerFolder()` / `loadFolder()` before use.
   */
  rootIpnsKeypair?: { publicKey: Uint8Array; privateKey: Uint8Array };
  /** TEE keys for IPNS key wrapping */
  teeKeys?: TeeKeys;
  /**
   * Callbacks for share-aware operations (re-wrapping).
   *
   * When provided, the SDK will automatically re-wrap file and folder keys
   * for share recipients after uploadFile() and createFolder(). This ensures
   * recipients can decrypt items added to shared folders after the share
   * was created.
   *
   * If not provided, re-wrapping is skipped (consumer must handle it).
   */
  shareCallbacks?: ShareCallbacks;
  /** Callback when an operation starts */
  onOperationStart?: (operation: string) => void;
  /** Callback when an operation completes */
  onOperationEnd?: (operation: string) => void;
  /** Callback when an error occurs */
  onError?: (error: Error) => void;
  /** Extra headers sent with every request (e.g., throttle bypass for testing). */
  defaultHeaders?: Record<string, string>;
  /**
   * Pre-built axios instance to use for all API calls.
   * When provided, the client uses this instead of creating its own instance.
   * Use this to share a single instance with the orval singleton (web app)
   * or to inject a fully-configured instance with 401 refresh logic.
   */
  axiosInstance?: AxiosInstance;
  /**
   * BYO-IPFS pinning configuration.
   * When omitted, all pins go through CipherBox infrastructure (default).
   */
  pinningConfig?: PinningConfig;
};

/**
 * Internal state for a loaded folder.
 *
 * Tracks everything needed to read and update a folder's metadata.
 * This is SDK-internal state -- consumers receive simplified events.
 */
export type FolderState = {
  /** IPNS name identifying this folder */
  ipnsName: string;
  /** Decrypted AES-256 folder key */
  folderKey: Uint8Array;
  /** Ed25519 IPNS keypair for signing updates */
  ipnsKeypair: { publicKey: Uint8Array; privateKey: Uint8Array };
  /** Current IPNS sequence number (monotonically increasing) */
  sequenceNumber: bigint;
  /** Current folder children (sealed child refs — phase 63 populates via read-chain navigation) */
  children: SealedChildRef[];
  /** Full decrypted folder node, or null if not yet loaded */
  metadata: Node | null;
  /** Timestamp (ms) of last successful load from IPNS */
  lastLoadedAt: number;
  /**
   * Stable UUID of the folder's underlying Node (D-06).
   * Populated on both registerFolder (from the registered node) and loadFolder
   * (from result.metadata.id). Never changes across publish cycles — rotation
   * bumps generation but keeps the same id.
   */
  nodeId: string;
  /**
   * Rotation/convergence counter of the folder's underlying Node (D-06).
   * Populated from the sealed Node's generation field. Never reset to 0 after
   * the first publish — monotonically increasing per rotation step.
   */
  nodeGeneration: number;
};

/**
 * Internal state for a loaded SHARED folder, keyed by `shareId`.
 *
 * Unlike {@link FolderState}, a shared folder carries the full
 * `SharedWriteContext` surface: distinct owner + recipient secp256k1 public
 * keys, the share's IPNS private key, the `shareId`, and the `addShareKeysFn`
 * callback. Shared folders are tracked in a SIBLING `SharedFolderTree` (NOT in
 * `folderTree`) because two shares can collide on `ipnsName` and each carries a
 * distinct write context — keying by `shareId` keeps them isolated (D REQ-3,
 * decision A4; research Pattern 2).
 */
export type SharedFolderState = {
  /** Share ID — the key under which this state lives in SharedFolderTree */
  shareId: string;
  /** IPNS name of the shared folder */
  ipnsName: string;
  /** Decrypted AES-256 folder key for the shared folder (also used as readKey) */
  folderKey: Uint8Array;
  /** Ed25519 IPNS private key for signing publishes of this shared folder */
  ipnsPrivateKey: Uint8Array;
  /** 32-byte AES key for unsealing the write-body (Phase 65 write-body model) */
  writeKey: Uint8Array;
  /** Current on-wire published envelope for unsealing the write-body */
  publishedNode: PublishedNode;
  /** Current IPNS sequence number (monotonically increasing) */
  sequenceNumber: bigint;
  /** Current folder children (sealed child refs — phase 63 populates via read-chain navigation) */
  children: SealedChildRef[];
  /** Sharer's secp256k1 public key (SealedChildRef readKeys wrap for owner) */
  ownerPublicKey: Uint8Array;
  /** Current user's secp256k1 public key (share_keys entries wrap for recipient) */
  recipientPublicKey: Uint8Array;
  /** Callback to add share keys for the recipient (same signature as SharedWriteContext) */
  addShareKeysFn: (
    shareId: string,
    keys: Array<{ keyType: ShareKeyType; itemId: string; encryptedKey: string }>
  ) => Promise<void>;
};
