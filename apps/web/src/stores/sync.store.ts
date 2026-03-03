import { create } from 'zustand';

type SyncStatus = 'idle' | 'syncing' | 'success' | 'error' | 'conflict';

type SyncState = {
  // Sync status
  status: SyncStatus;
  lastSyncTime: Date | null;
  syncError: string | null;

  // Conflict state
  conflictMessage: string | null;

  // Initial sync tracking
  initialSyncComplete: boolean;

  // Network status
  isOnline: boolean;

  // Actions
  startSync: () => void;
  syncSuccess: () => void;
  syncFailure: (error: string) => void;
  setConflict: (message: string) => void;
  clearConflict: () => void;
  completeInitialSync: () => void;
  setOnline: (online: boolean) => void;
  reset: () => void;
};

/**
 * Sync state store for multi-device sync.
 *
 * Tracks:
 * - Sync status (idle/syncing/success/error/conflict)
 * - Last sync timestamp
 * - Sync errors
 * - Conflict messages (set during 409 re-sync, cleared after retry)
 * - Network online status
 *
 * Used by useSyncPolling hook and SyncIndicator component.
 */
export const useSyncStore = create<SyncState>((set) => ({
  // Initial state
  status: 'idle',
  lastSyncTime: null,
  syncError: null,
  conflictMessage: null,
  initialSyncComplete: false,
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

  setConflict: (message) =>
    set({
      status: 'conflict',
      conflictMessage: message,
    }),

  clearConflict: () =>
    set({
      conflictMessage: null,
    }),

  completeInitialSync: () => set({ initialSyncComplete: true }),

  setOnline: (online) => set({ isOnline: online }),

  reset: () =>
    set({
      status: 'idle',
      lastSyncTime: null,
      syncError: null,
      conflictMessage: null,
      initialSyncComplete: false,
    }),
}));
