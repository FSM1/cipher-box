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
import type { FolderNode } from '../stores/folder.store';

let _client: CipherBoxClient | null = null;

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
  _client = new CipherBoxClient(config);
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

  // Guard: don't register placeholder folders that haven't loaded yet —
  // empty key material would cause crypto/IPNS errors on subsequent mutations
  if (!folder.isLoaded || folder.folderKey.length === 0 || folder.ipnsPrivateKey.length === 0) {
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
