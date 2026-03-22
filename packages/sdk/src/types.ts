/**
 * @cipherbox/sdk - Type definitions
 *
 * Client configuration and internal state types for the SDK.
 * These types define the contract between the SDK and its consumers.
 */

import type { TeeKeys } from '@cipherbox/sdk-core';
import type { AxiosInstance } from '@cipherbox/api-client';
import type { FolderChild, FolderMetadata } from '@cipherbox/core';
import type { SentShareInfo } from './share';

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
  /** Current folder children (files and subfolders) */
  children: FolderChild[];
  /** Full decrypted folder metadata, or null if not yet loaded */
  metadata: FolderMetadata | null;
  /** Timestamp (ms) of last successful load from IPNS */
  lastLoadedAt: number;
};
