import { create } from 'zustand';
import type { BinEntry } from '@cipherbox/crypto';

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
  addEntry: (entry: BinEntry) => void;
  removeEntry: (entryId: string) => void;
  removeEntries: (entryIds: string[]) => void;
  setLoading: (loading: boolean) => void;
  setLoaded: (loaded: boolean) => void;
  setError: (error: string | null) => void;
  setBinIpnsName: (name: string) => void;
  setRetentionDays: (days: number) => void;
  clearBin: () => void;
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

  addEntry: (entry) =>
    set((state) => ({
      entries: [...state.entries, entry],
      sequenceNumber: state.sequenceNumber + 1,
    })),

  removeEntry: (entryId) =>
    set((state) => ({
      entries: state.entries.filter((e) => e.id !== entryId),
      sequenceNumber: state.sequenceNumber + 1,
    })),

  removeEntries: (entryIds) =>
    set((state) => {
      const ids = new Set(entryIds);
      return {
        entries: state.entries.filter((e) => !ids.has(e.id)),
        sequenceNumber: state.sequenceNumber + 1,
      };
    }),

  setLoading: (loading) => set({ isLoading: loading }),

  setLoaded: (loaded) => set({ isLoaded: loaded }),

  setError: (error) => set({ error }),

  setBinIpnsName: (name) => set({ binIpnsName: name }),

  setRetentionDays: (days) => set({ retentionDays: days }),

  clearBin: () =>
    set({
      entries: [],
      isLoading: false,
      isLoaded: false,
      error: null,
      sequenceNumber: 0,
      binIpnsName: null,
      retentionDays: 30,
    }),
}));
