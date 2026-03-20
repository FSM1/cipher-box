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
 * Safe to call multiple times -- just overwrites with current state.
 */
export function ensureFolderRegistered(folder: FolderNode): void {
  const client = getSdkClient();
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
