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
export { CipherBoxClient, BinNotLoadedError } from './client';

// Types
export type { CipherBoxClientConfig, FolderState, ShareCallbacks, PinningConfig } from './types';

// Events
export type { SdkEvent, SdkEventHandler } from './events';
export { SdkEventEmitter } from './events';

// Bin operations (types only -- operations accessed via CipherBoxClient)
export type { BinOperationContext, BinState } from './bin';

// Share operations (types only -- operations accessed via CipherBoxClient)
export type {
  ShareOperationContext,
  SentShareInfo,
  SharedWriteContext,
  ShareKeyType,
  SharedWriteContextParams,
  CachedShareKey,
} from './share';

// Shared-write operations (stateless functions for write-share recipients)
export {
  uploadToSharedFolder,
  createSharedSubfolder,
  renameInSharedFolder,
  deleteFromSharedFolder,
  updateSharedFile,
  updateSharePermission,
  buildSharedWriteContext,
  ShareKeyCache,
} from './share';

// Error handling and retry utilities
export {
  isForbiddenError,
  isConflictError,
  withRevocationGuard,
  withConflictRetry,
} from './error';
