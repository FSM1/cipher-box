import { create } from 'zustand';

type SyncStatus = 'idle' | 'syncing' | 'success' | 'error';

type SyncState = {
  // Sync status
  status: SyncStatus;
  lastSyncTime: Date | null;
  syncError: string | null;

  // Network status
  isOnline: boolean;

  // Actions
  startSync: () => void;
  syncSuccess: () => void;
  syncFailure: (error: string) => void;
  setOnline: (online: boolean) => void;
  reset: () => void;
};

/**
 * Sync state store for multi-device sync.
 *
 * Tracks:
 * - Sync status (idle/syncing/success/error)
 * - Last sync timestamp
 * - Sync errors
 * - Network online status
 *
 * Used by useSyncPolling hook and SyncIndicator component.
 */
export const useSyncStore = create<SyncState>((set) => ({
  // Initial state
  status: 'idle',
  lastSyncTime: null,
  syncError: null,
  isOnline: typeof navigator !== 'undefined' ? navigator.onLine : true,

  // Actions
  startSync: () =>
    set({
      status: 'syncing',
      syncError: null,
    }),

  syncSuccess: () =>
    set({
      status: 'success',
      lastSyncTime: new Date(),
      syncError: null,
    }),

  syncFailure: (error) =>
    set({
      status: 'error',
      syncError: error,
    }),

  setOnline: (online) => set({ isOnline: online }),

  reset: () =>
    set({
      status: 'idle',
      lastSyncTime: null,
      syncError: null,
    }),
}));
