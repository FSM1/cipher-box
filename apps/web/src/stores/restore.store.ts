import { create } from 'zustand';

/**
 * Restore status state machine (D-05).
 *
 * Mirrors the download store's status shape, but restore is a metadata-only
 * operation (bin entry re-linking + IPNS publish) with no byte stream — so
 * this store deliberately omits the download store's byte-count fields.
 */
type RestoreStatus = 'idle' | 'restoring' | 'success' | 'error';

type RestoreState = {
  status: RestoreStatus;
  currentItem: string | null;
  error: string | null;

  startRestore: (itemName: string) => void;
  setRestoreSuccess: () => void;
  setRestoreError: (error: string) => void;
  resetRestore: () => void;
};

export const useRestoreStore = create<RestoreState>((set) => ({
  status: 'idle',
  currentItem: null,
  error: null,

  startRestore: (itemName) =>
    set({
      status: 'restoring',
      currentItem: itemName,
      error: null,
    }),

  setRestoreSuccess: () =>
    set({
      status: 'success',
      currentItem: null,
    }),

  setRestoreError: (error) =>
    set({
      status: 'error',
      error,
      currentItem: null,
    }),

  resetRestore: () =>
    set({
      status: 'idle',
      currentItem: null,
      error: null,
    }),
}));
