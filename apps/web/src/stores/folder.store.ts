import { create } from 'zustand';
import type { SealedChildRef } from '@cipherbox/core';
import type { ResolvedChild } from '@cipherbox/sdk';
import type { CipherBoxClient } from '@cipherbox/sdk';
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
  /**
   * Resolved children for display — kind/size/modifiedAt pre-resolved by the
   * SDK (68.2-02 `ResolvedChild[]`). The SDK's `folderTree` is the single
   * owner of the raw `SealedChildRef[]` write-path identity; this store is a
   * pure display projection and never independently resolves (SC#3, D-01).
   */
  children: ResolvedChild[];
  /**
   * Raw sealed children (write-path/crypto identity carrier) — the SDK's
   * `folderTree` is the source of truth; this is a same-session mirror
   * populated from `ensureFolderLoaded`/`listFolder` call sites (nav,
   * resync, poll) wherever raw `readKeySealed`/`generation`/`versionFloor`
   * are needed (e.g. `resolveFileMetadata`). Optional — a folder that has
   * only ever received the display `children` projection (no raw
   * fetch yet) simply has none; write-path callers guard with `?? []`.
   */
  rawChildren?: SealedChildRef[];
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
  updateFolderChildren: (folderId: string, children: ResolvedChild[]) => void;
  updateFolderRawChildren: (folderId: string, rawChildren: SealedChildRef[]) => void;
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

  updateFolderRawChildren: (folderId, rawChildren) =>
    set((state) => {
      const folder = state.folders[folderId];
      if (!folder) return state;

      return {
        folders: {
          ...state.folders,
          [folderId]: { ...folder, rawChildren },
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
            // folder's NON-EMPTY children at or below the store's current
            // sequence — an empty/mismatched event here would silently blank
            // a loaded ancestor's rendered contents (breadcrumb-up
            // empty-flash). A genuinely-emptied folder IS adopted: its real
            // mutation (e.g. deleteToBin removing the last child) lands with
            // a NEWER sequenceNumber than the store holds, so the guard only
            // rejects an empty-over-populated event at or below the store's
            // sequence (the stale/mismatched re-walk class).
            if (
              matchingFolder.isLoaded &&
              matchingFolder.children.length > 0 &&
              event.children.length === 0 &&
              matchingFolder.sequenceNumber >= event.sequenceNumber
            ) {
              logger.warn(
                `[folder.store] Ignoring ${event.type} for ${event.ipnsName}: event carries empty children but the store already has ${matchingFolder.children.length} loaded — refusing to blank a loaded ancestor`
              );
              break;
            }

            // T-68.1-33-01: `ResolvedChild[]` arrives fully resolved (kind
            // pre-resolved by the SDK, 68.2-02) — the store is a pure
            // projection and never independently resolves (SC#3, D-01). A
            // straight synchronous update is safe; only the stale-event
            // guard below is needed. Strict `>` so an equal-or-newer event is
            // still adopted — the delete-last-item mutation lands at a NEWER
            // sequence, so it passes untouched.
            if (matchingFolder.sequenceNumber > event.sequenceNumber) break;
            get().updateFolderChildren(matchingFolder.id, event.children);
            get().updateFolderSequence(matchingFolder.id, event.sequenceNumber);
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
