/**
 * @cipherbox/sdk
 *
 * Stateful SDK client for CipherBox. Orchestrates folder CRUD, file upload/download,
 * bin operations, and share operations with internal state management and
 * event-driven change notification.
 *
 * Usage:
 * ```typescript
 * import { CipherBoxClient, type CipherBoxClientConfig } from '@cipherbox/sdk';
 *
 * const client = new CipherBoxClient({
 *   apiUrl: 'https://api.cipherbox.cc',
 *   getAccessToken: () => authStore.getAccessToken(),
 *   vaultKeypair: { publicKey, privateKey },
 *   rootIpnsName: 'k51...',
 *   rootFolderKey: decryptedRootKey,
 * });
 *
 * // Subscribe to events
 * const unsub = client.on((event) => {
 *   if (event.type === 'folder:updated') {
 *     zustandStore.updateFolder(event.folderId, event.children);
 *   }
 * });
 *
 * // Load root folder
 * await client.loadFolder(rootIpnsName, rootFolderKey, rootIpnsKeypair);
 *
 * // Cleanup
 * unsub();
 * client.destroy();
 * ```
 */

// Main client
export { CipherBoxClient } from './client';

// Types
export type { CipherBoxClientConfig, FolderState } from './types';

// Events
export type { SdkEvent, SdkEventHandler } from './events';
export { SdkEventEmitter } from './events';
