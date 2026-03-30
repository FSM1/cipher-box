/**
 * SDK Provider - CipherBoxClient lifecycle management
 *
 * Manages a singleton CipherBoxClient instance for the web app.
 * Created after vault load (login complete), destroyed on logout.
 *
 * The SDK client is the single source of truth for all file operations.
 * Hooks call client methods, and stores subscribe to client events.
 */
import { CipherBoxClient, type CipherBoxClientConfig } from '@cipherbox/sdk';
import type { PinningConfig } from '@cipherbox/sdk';
import { apiAxios } from './api-config';
import { destroyEncryptionWorker } from '../services/encrypt-worker.service';
import type { FolderNode } from '../stores/folder.store';

let _client: CipherBoxClient | null = null;
let _lastConfig: CipherBoxClientConfig | null = null;

/**
 * Initialize the SDK client. Called after vault is loaded (login complete).
 * The client persists for the session and is destroyed on logout.
 *
 * If a client already exists (e.g., session restoration), it is destroyed
 * before creating the new one.
 */
export function initSdkClient(config: CipherBoxClientConfig): CipherBoxClient {
  if (_client) {
    _client.destroy();
  }
  // Inject the shared axios instance so CipherBoxClient uses the same
  // instance as orval-generated functions (single instance, no dual path).
  _lastConfig = { ...config };
  _client = new CipherBoxClient({ ...config, axiosInstance: apiAxios });
  return _client;
}

/**
 * Get the current SDK client instance.
 * Throws if called before initSdkClient() (i.e., before login).
 */
export function getSdkClient(): CipherBoxClient {
  if (!_client) {
    throw new Error('SDK client not initialized. Call initSdkClient() after login.');
  }
  return _client;
}

/**
 * Check if the SDK client is initialized (for conditional usage).
 */
export function hasSdkClient(): boolean {
  return _client !== null;
}

/**
 * Destroy the SDK client. Called on logout.
 * Clears internal state, key caches, and event subscriptions.
 */
export function destroySdkClient(): void {
  if (_client) {
    _client.destroy();
    _client = null;
  }
  _lastConfig = null;
  // Terminate encryption Web Worker (no-op if not initialized)
  destroyEncryptionWorker();
}

/**
 * Reconfigure the SDK client's pinning config at runtime.
 * Called from StorageTab after saving new BYO settings.
 *
 * Destroys the current client and recreates it with updated pinningConfig
 * while preserving all other configuration. This is acceptable since config
 * changes are infrequent (only on Settings save).
 */
export function reconfigurePinning(pinningConfig?: PinningConfig): void {
  if (!_client || !_lastConfig) return;
  _client.destroy();
  _lastConfig = { ..._lastConfig, pinningConfig };
  _client = new CipherBoxClient({ ..._lastConfig, axiosInstance: apiAxios });
}

/**
 * Ensure a folder from the Zustand store is registered in the SDK's
 * internal FolderTree. This bridges the gap between folder navigation
 * (which loads folders into Zustand) and SDK operations (which require
 * folders in the SDK's internal state).
 *
 * Only registers if the SDK doesn't already have the folder. The SDK's
 * internal state (sequence number, children, keys) is authoritative once
 * a folder is registered — all mutations go through the SDK.
 */
export function ensureFolderRegistered(folder: FolderNode): void {
  const client = getSdkClient();

  // Don't overwrite if SDK already has this folder — its internal state
  // is authoritative (correct sequence number, keys, children from mutations)
  if (client.hasFolder(folder.ipnsName)) return;

  // Guard: don't register placeholder folders with empty key material —
  // would cause crypto/IPNS errors on subsequent mutations
  if (folder.folderKey.length === 0 || folder.ipnsPrivateKey.length === 0) {
    return;
  }

  client.registerFolder(
    folder.ipnsName,
    folder.folderKey,
    {
      publicKey: new Uint8Array(0), // Public key derived from private key when needed
      privateKey: folder.ipnsPrivateKey,
    },
    folder.children,
    folder.sequenceNumber
  );
}
