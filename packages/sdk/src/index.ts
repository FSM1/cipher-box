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
export { CipherBoxClient, BinNotLoadedError, ReconcileStaleError } from './client';

// Types
export type {
  CipherBoxClientConfig,
  FolderState,
  SharedFolderState,
  PinningConfig,
  RotationClientCallbacks,
  LocalGrantRecord,
} from './types';

// SDK-owned resolved folder listings (SDK-READ-02, D-02) -- the single
// per-child metadata answer returned by client.listFolder/listSharedFolder
// and carried on folder:loaded/folder:updated/sharedFolder:updated events.
// Type-only export: the web consumes ResolvedChild for rendering, never
// constructs one itself (D-07).
export type { ResolvedChild } from './folder-listing';

// Shared-folder state (sibling tree keyed by shareId)
export { SharedFolderTree } from './state/shared-folder-tree';

// Durable rotation high-water state machine (ROT-07) -- monotonic-max
// generation + seq floors over a SINGLE combined injected HighWaterStore
// seam (SC#4/D-06), and the enforceResolved fail-closed regression gate.
// apps/web supplies the IndexedDB-backed HighWaterStore (68-06, 70.1-02).
export {
  createRotationHighWater,
  GenerationRegressionError,
  SequenceRegressionError,
} from './state/rotation-high-water';
export type {
  HighWaterStore,
  RotationHighWater,
  EnforceResolvedParams,
  CombinedFloorRecord,
} from './state/rotation-high-water';

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
  buildSharedWriteContext,
  ShareKeyCache,
  CannotWriteUntilRefetchError,
} from './share';

// Owner-reconcile driver (D-10/D-11) -- drives sdk-core's reMintGrantsRootedAt
// with callbacks assembled from an injected transport (owner-reconcile.ts,
// unit-tested here in packages/sdk). apps/web supplies the concrete
// api-client transport as a thin, untested wrapper (68-07).
export {
  buildGrantRemintCallbacks,
  runOwnerReconcile,
  type OwnerReconcileTransport,
  type GrantRow,
} from './share';

// Error handling and retry utilities
export { isForbiddenError, isConflictError, withRevocationGuard, withConflictRetry } from './error';

// Pure structural utils (D-07 write scope) -- no crypto/IO, re-exported so
// apps/web imports these from the facade instead of @cipherbox/sdk-core
// directly (RESEARCH Code Examples: MoveDialog.tsx, useFolderMutations.ts,
// streaming-crypto.service.ts current call sites).
export {
  getDepth,
  isDescendantOf,
  calculateSubtreeDepth,
  type TreeNode,
} from '@cipherbox/sdk-core';
export { selectEncryptionMode } from '@cipherbox/sdk-core';
// Pure recipient-pin compare (80-04, D-03d) -- no crypto/IO beyond byte
// normalization; re-exported so ShareDialog's upgrade path (80-08 consumer 3)
// verifies the server-fed recipient against the node's owner-sealed pin list
// via the facade instead of importing @cipherbox/sdk-core directly (D-07).
export { assertRecipientPinned } from '@cipherbox/sdk-core';

// D-07 full-boundary facade types (68.2-04) -- the web consumes these to call
// client.bootstrapVaultKeys/serializeVault/deserializeVault (vault-bootstrap)
// and client.deriveRegistryIpnsKeypair/encryptRegistry/decryptRegistry
// (device-registry) without importing @cipherbox/core directly.
export type { VaultInit, DeviceRegistry } from '@cipherbox/core';

// D-07 full-boundary facade type (68.2-04) -- consumed by
// client.testConnection (BYO-pinning passthrough, no ROT-07 gate).
export type { ConnectionTestResult } from '@cipherbox/sdk-core';

// D-07 full-boundary re-export (68.2-10 cutover) -- vault-settings runtime
// constant/validator + type, consumed by vault-settings.service.ts,
// vault-settings.store.ts, and VaultTab.tsx instead of importing
// @cipherbox/core directly (68.2-PATTERNS.md flags this as a remaining
// literal-wording D-07 violation; this closes it).
export { DEFAULT_VAULT_SETTINGS, validateVaultSettings } from '@cipherbox/core';
export type { VaultSettings } from '@cipherbox/core';
