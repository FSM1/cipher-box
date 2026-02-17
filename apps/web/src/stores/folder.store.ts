import { create } from 'zustand';
import type { FolderChildV2 } from '@cipherbox/crypto';

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
  /** Decrypted children (files and subfolders) */
  children: FolderChildV2[];
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
  updateFolderChildren: (folderId: string, children: FolderChildV2[]) => void;
  updateFolderSequence: (folderId: string, sequenceNumber: bigint) => void;
  setCurrentFolder: (folderId: string | null) => void;
  setBreadcrumbs: (breadcrumbs: Breadcrumb[]) => void;
  addPendingPublish: (folderId: string) => void;
  removePendingPublish: (folderId: string) => void;
  removeFolder: (folderId: string) => void;
  updateFolderName: (folderId: string, newName: string) => void;
  clearFolders: () => void;
};

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
}));

// Expose store on window for E2E testing (development only)
if (typeof window !== 'undefined' && import.meta.env.DEV) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (window as any).__ZUSTAND_FOLDER_STORE__ = useFolderStore;
}
