/**
 * @cipherbox/sdk - Type definitions
 *
 * Client configuration and internal state types for the SDK.
 * These types define the contract between the SDK and its consumers.
 */

import type { TeeKeys } from '@cipherbox/sdk-core';
import type { FolderChild, FolderMetadata } from '@cipherbox/core';

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
  /** Callback when an operation starts */
  onOperationStart?: (operation: string) => void;
  /** Callback when an operation completes */
  onOperationEnd?: (operation: string) => void;
  /** Callback when an error occurs */
  onError?: (error: Error) => void;
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
