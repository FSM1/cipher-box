import { create } from 'zustand';
import type { BinEntry } from '@cipherbox/crypto';
import type { CipherBoxClient } from '@cipherbox/sdk';

type BinState = {
  /** Current bin entries */
  entries: BinEntry[];
  /** True while loading bin metadata from IPNS */
  isLoading: boolean;
  /** True after first successful load */
  isLoaded: boolean;
  /** Last error message, null = no error */
  error: string | null;
  /** Monotonically increasing update counter (metadata-level, not IPNS-level) */
  sequenceNumber: number;
  /** IPNS name for the bin record (display/debug) */
  binIpnsName: string | null;
  /** Retention period from API config (days) */
  retentionDays: number;

  // Actions
  setEntries: (entries: BinEntry[], seq: number) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setBinIpnsName: (name: string) => void;
  setRetentionDays: (days: number) => void;
  clearBin: () => void;

  // SDK event subscription
  subscribeToSdk: (client: CipherBoxClient) => void;
  _sdkUnsubscribe: (() => void) | null;
};

/**
 * Bin store for managing recycle bin state.
 *
 * Tracks soft-deleted items with their metadata, loading state,
 * and IPNS name. Cleared on logout for clean lifecycle.
 *
 * Used by:
 * - useAuth (bin initialization after login, clear on logout)
 * - useBin (CRUD operations, auto-purge)
 * - useFolderMutations (addToBin on delete)
 */
export const useBinStore = create<BinState>((set) => ({
  // State
  entries: [],
  isLoading: false,
  isLoaded: false,
  error: null,
  sequenceNumber: 0,
  binIpnsName: null,
  retentionDays: 30,

  // Actions
  setEntries: (entries, seq) =>
    set({
      entries,
      sequenceNumber: seq,
      isLoaded: true,
      isLoading: false,
      error: null,
    }),

  setLoading: (loading) => set({ isLoading: loading }),

  setError: (error) => set({ error }),

  setBinIpnsName: (name) => set({ binIpnsName: name }),

  setRetentionDays: (days) =>
    set({
      retentionDays: Number.isFinite(days) ? Math.max(0, Math.floor(days)) : 30,
    }),

  clearBin: () => {
    const state = useBinStore.getState();
    // Unsubscribe from SDK events before clearing
    if (state._sdkUnsubscribe) {
      state._sdkUnsubscribe();
    }

    set({
      entries: [],
      isLoading: false,
      isLoaded: false,
      error: null,
      sequenceNumber: 0,
      binIpnsName: null,
      retentionDays: 30,
      _sdkUnsubscribe: null,
    });
  },

  // SDK event subscription
  _sdkUnsubscribe: null,

  /**
   * Subscribe to SDK bin events. Called after SDK client is initialized.
   * Updates bin entries when the SDK emits bin:updated events.
   */
  subscribeToSdk: (client: CipherBoxClient) => {
    // Unsubscribe any existing subscription
    const currentUnsub = useBinStore.getState()._sdkUnsubscribe;
    if (currentUnsub) {
      currentUnsub();
    }

    const unsubscribe = client.on((event) => {
      if (event.type === 'bin:updated') {
        const currentSeq = useBinStore.getState().sequenceNumber;
        set({
          entries: event.entries,
          sequenceNumber: currentSeq + 1,
          isLoaded: true,
          isLoading: false,
          error: null,
        });
      }
    });

    set({ _sdkUnsubscribe: unsubscribe });
  },
}));
