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
 * Registers the folder if the SDK doesn't already track it. If it does, the
 * SDK's internal state is authoritative for SDK-routed mutations, but is
 * reconciled forward when the store has observed a strictly-newer IPNS sequence
 * (e.g. from a direct file replace/version publish) to avoid stale-sequence 409s
 * and merge-driven resurrection of deleted items.
 */
export function ensureFolderRegistered(folder: FolderNode): void {
  const client = getSdkClient();

  // Already tracked: the SDK folderTree is authoritative for SDK-routed
  // mutations, but the Zustand store can advance *past* it when the web app
  // publishes folder metadata directly via sdk-core (e.g. file replace/version
  // edits bump modifiedAt + sequence in the store without routing through the
  // client). Reconcile so a following SDK mutation (delete/move) doesn't publish
  // with a stale sequence (→ 409) against a stale base, which the 409 merge would
  // resolve by resurrecting the just-deleted child. Only adopted when strictly
  // newer, so SDK-advanced state stays authoritative.
  if (client.hasFolder(folder.ipnsName)) {
    client.reconcileFolderState(folder.ipnsName, folder.children, folder.sequenceNumber);
    return;
  }

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
