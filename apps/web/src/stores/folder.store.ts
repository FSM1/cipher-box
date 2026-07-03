import { create } from 'zustand';
import type { SealedChildRef } from '@cipherbox/core';
import type { CipherBoxClient } from '@cipherbox/sdk';
import { getKind, resolveKinds } from '../lib/kind-cache';
import { logger } from '../lib/logger';

/**
 * A folder node in the in-memory folder tree.
 * Contains decrypted folder data and navigation state.
 */
export type FolderNode = {
  /** UUID for internal reference (null string 'root' for root folder) */
  id: string;
  /** Folder name */
  name: string;
  /** IPNS name for this folder (k51.../bafzaa... format) */
  ipnsName: string;
  /** Parent folder ID (null for root) */
  parentId: string | null;
  /** Decrypted children (sealed child refs — phase 63 populates via read-chain navigation) */
  children: SealedChildRef[];
  /** Has metadata been fetched and decrypted? */
  isLoaded: boolean;
  /** Is metadata currently being fetched? */
  isLoading: boolean;
  /** Current IPNS sequence number */
  sequenceNumber: bigint;
  /** Decrypted AES-256 folder key */
  folderKey: Uint8Array;
  /** Decrypted Ed25519 IPNS private key */
  ipnsPrivateKey: Uint8Array;
};

/**
 * Breadcrumb entry for navigation.
 */
type Breadcrumb = {
  id: string;
  name: string;
};

type FolderState = {
  // Folder tree indexed by id
  folders: Record<string, FolderNode>;

  // Current navigation
  currentFolderId: string | null; // null = root
  breadcrumbs: Breadcrumb[];

  // Publishing state
  pendingPublishes: Set<string>; // folder IDs with pending IPNS publishes

  // Actions
  setFolder: (folder: FolderNode) => void;
  updateFolderChildren: (folderId: string, children: SealedChildRef[]) => void;
  updateFolderSequence: (folderId: string, sequenceNumber: bigint) => void;
  setCurrentFolder: (folderId: string | null) => void;
  setBreadcrumbs: (breadcrumbs: Breadcrumb[]) => void;
  addPendingPublish: (folderId: string) => void;
  removePendingPublish: (folderId: string) => void;
  removeFolder: (folderId: string) => void;
  updateFolderName: (folderId: string, newName: string) => void;
  clearFolders: () => void;

  // SDK event subscription
  subscribeToSdk: (client: CipherBoxClient) => void;
};

// Module-level unsubscribe callback — not part of Zustand state to avoid spurious re-renders
let _folderSdkUnsubscribe: (() => void) | null = null;

/**
 * Folder store for managing folder tree state.
 *
 * Maintains the in-memory representation of the folder hierarchy
 * with decrypted folder keys and metadata.
 *
 * SECURITY: All folder keys are memory-only - never persisted to storage.
 * Call clearFolders() on logout to zero-fill all key material.
 */
export const useFolderStore = create<FolderState>((set, get) => ({
  // State
  folders: {},
  currentFolderId: null,
  breadcrumbs: [],
  pendingPublishes: new Set<string>(),

  // Actions
  setFolder: (folder) =>
    set((state) => ({
      folders: { ...state.folders, [folder.id]: folder },
    })),

  updateFolderChildren: (folderId, children) =>
    set((state) => {
      const folder = state.folders[folderId];
      if (!folder) return state;

      return {
        folders: {
          ...state.folders,
          [folderId]: { ...folder, children, isLoaded: true, isLoading: false },
        },
      };
    }),

  updateFolderSequence: (folderId, sequenceNumber) =>
    set((state) => {
      const folder = state.folders[folderId];
      if (!folder) return state;

      return {
        folders: {
          ...state.folders,
          [folderId]: { ...folder, sequenceNumber },
        },
      };
    }),

  setCurrentFolder: (folderId) => set({ currentFolderId: folderId }),

  setBreadcrumbs: (breadcrumbs) => set({ breadcrumbs }),

  addPendingPublish: (folderId) =>
    set((state) => {
      const newPending = new Set(state.pendingPublishes);
      newPending.add(folderId);
      return { pendingPublishes: newPending };
    }),

  removePendingPublish: (folderId) =>
    set((state) => {
      const newPending = new Set(state.pendingPublishes);
      newPending.delete(folderId);
      return { pendingPublishes: newPending };
    }),

  // Remove a folder from local state (after deletion)
  // Also clears the folder's key material from memory
  removeFolder: (folderId) =>
    set((state) => {
      const folder = state.folders[folderId];
      if (!folder) return state;

      // Zero-fill keys before removing
      if (folder.folderKey) folder.folderKey.fill(0);
      if (folder.ipnsPrivateKey) folder.ipnsPrivateKey.fill(0);

      const { [folderId]: _removed, ...remainingFolders } = state.folders;
      void _removed; // Intentionally destructured to remove from object
      return { folders: remainingFolders };
    }),

  // Update a folder's name in local state
  updateFolderName: (folderId, newName) =>
    set((state) => {
      const folder = state.folders[folderId];
      if (!folder) return state;

      return {
        folders: {
          ...state.folders,
          [folderId]: { ...folder, name: newName },
        },
      };
    }),

  // [SECURITY: MEDIUM-02] Zero-fill sensitive key material before clearing
  clearFolders: () => {
    const state = get();

    // Unsubscribe from SDK events before clearing
    if (_folderSdkUnsubscribe) {
      _folderSdkUnsubscribe();
      _folderSdkUnsubscribe = null;
    }

    // Best-effort memory clearing - overwrite all folder keys with zeros
    for (const folder of Object.values(state.folders)) {
      if (folder.folderKey) {
        folder.folderKey.fill(0);
      }
      if (folder.ipnsPrivateKey) {
        folder.ipnsPrivateKey.fill(0);
      }
    }

    set({
      folders: {},
      currentFolderId: null,
      breadcrumbs: [],
      pendingPublishes: new Set<string>(),
    });
  },

  /**
   * Subscribe to SDK folder events. Called after SDK client is initialized.
   *
   * Maps SDK events (keyed by ipnsName) to store updates (keyed by folder id).
   * The SDK emits folderId = ipnsName, so we reverse-lookup to find the store's folder id.
   */
  subscribeToSdk: (client: CipherBoxClient) => {
    // Unsubscribe any existing subscription
    if (_folderSdkUnsubscribe) {
      _folderSdkUnsubscribe();
    }

    _folderSdkUnsubscribe = client.on((event) => {
      switch (event.type) {
        case 'folder:loaded':
        case 'folder:updated': {
          // SDK uses ipnsName as folderId; find the matching store entry
          const folders = get().folders;
          const matchingFolder = Object.values(folders).find((f) => f.ipnsName === event.ipnsName);
          if (matchingFolder) {
            // T-68.1-26-01: a folder:updated/folder:loaded event carrying an
            // EMPTY children array must never replace an already-loaded
            // folder's NON-EMPTY children — an empty/mismatched event here
            // would silently blank a loaded ancestor's rendered contents
            // (breadcrumb-up empty-flash). A genuinely-emptied folder IS
            // adopted: its real mutation (e.g. deleteToBin removing the last
            // child) lands with a NEWER sequenceNumber than the store holds,
            // so the guard only rejects an empty-over-populated event at or
            // below the store's sequence (the stale/mismatched re-walk class;
            // fixed 68.1-29 — the original unconditional rejection broke
            // delete-last-item flows: recycle-bin TC02, bin-restore-after-reload).
            if (
              matchingFolder.isLoaded &&
              matchingFolder.children.length > 0 &&
              event.children.length === 0 &&
              event.sequenceNumber <= matchingFolder.sequenceNumber
            ) {
              logger.warn(
                `[folder.store] Ignoring ${event.type} for ${event.ipnsName}: event carries empty children but the store already has ${matchingFolder.children.length} loaded — refusing to blank a loaded ancestor`
              );
              break;
            }

            // T-68.1-33-01: hybrid resolve-before-insert projection, mirroring
            // navigateTo's D-02 ordering (useFolderNavigation.ts). When every
            // child's kind is already cached (or the children array is empty,
            // vacuously true — preserves 68.1-29 delete-last-item instant
            // behavior), project synchronously with no added latency. When at
            // least one child is a cache miss (e.g. first load after reload),
            // await resolveKinds BEFORE the children land, so a row is never
            // interactable while its kind is unresolved — closing the owner
            // file-browser race where a file row transiently renders as a
            // folder ([DIR]) and hides isFile-gated actions like "Edit".
            const allKindsCached = event.children.every(
              (ref) => getKind(ref.ipnsName) !== undefined
            );

            if (allKindsCached) {
              get().updateFolderChildren(matchingFolder.id, event.children);
              get().updateFolderSequence(matchingFolder.id, event.sequenceNumber);
              break;
            }

            // Capture locals — `event`/`matchingFolder` must not be read after
            // the await (matchingFolder is a snapshot, not live).
            const folderId = matchingFolder.id;
            const eventChildren = event.children;
            const eventSequence = event.sequenceNumber;

            // T-68.1-33-02: guarded async IIFE — never throws out of the
            // subscription handler (internal try/catch swallows resolveKinds
            // rejections; resolveKinds itself is already best-effort and
            // never rejects, but the catch is defense-in-depth).
            void (async () => {
              try {
                await resolveKinds(eventChildren);
              } catch {
                // Best-effort — fall through and still project folder-safe.
              }

              // Re-lookup: the folder may have been removed while resolving.
              const current = get().folders[folderId];
              if (!current) return;

              // Stale-event guard: a newer state may have landed (a
              // subsequent all-cached event, or a direct handleSync/
              // resyncFolder insert) while this cache-miss resolve was
              // in flight. Do not clobber it with the stale N.
              if (current.sequenceNumber > eventSequence) return;

              get().updateFolderChildren(folderId, eventChildren);
              get().updateFolderSequence(folderId, eventSequence);
            })();
          }
          break;
        }
        case 'folder:deleted': {
          // SDK uses ipnsName as folderId
          const folders = get().folders;
          const matchingFolder = Object.values(folders).find((f) => f.ipnsName === event.folderId);
          if (matchingFolder) {
            get().removeFolder(matchingFolder.id);
          }
          break;
        }
      }
    });
  },
}));

// Expose store on window for E2E testing (development only)
declare global {
  interface Window {
    __ZUSTAND_FOLDER_STORE__?: typeof useFolderStore;
  }
}

if (typeof window !== 'undefined' && import.meta.env.DEV) {
  window.__ZUSTAND_FOLDER_STORE__ = useFolderStore;
}
