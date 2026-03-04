import { create } from 'zustand';
import { vaultApi, QuotaResponse } from '../lib/api/vault';

const DEFAULT_LIMIT_BYTES = 500 * 1024 * 1024; // 500 MiB

const initialState = {
  usedBytes: 0,
  limitBytes: DEFAULT_LIMIT_BYTES,
  remainingBytes: DEFAULT_LIMIT_BYTES,
  loading: false,
  error: null as string | null,
};

type QuotaState = typeof initialState & {
  fetchQuota: () => Promise<void>;
  removeUsage: (bytes: number) => void;
  canUpload: (bytes: number) => boolean;
  reset: () => void;
};

export const useQuotaStore = create<QuotaState>((set, get) => ({
  ...initialState,

  fetchQuota: async () => {
    set({ loading: true, error: null });
    try {
      const quota: QuotaResponse = await vaultApi.getQuota();
      set({
        usedBytes: quota.usedBytes,
        limitBytes: quota.limitBytes,
        remainingBytes: quota.remainingBytes,
        loading: false,
      });
    } catch {
      set({ error: 'Failed to fetch quota', loading: false });
    }
  },

  removeUsage: (bytes) =>
    set((state) => ({
      usedBytes: Math.max(0, state.usedBytes - bytes),
      remainingBytes: Math.min(state.limitBytes, state.remainingBytes + bytes),
    })),

  canUpload: (bytes) => {
    const { remainingBytes } = get();
    return bytes <= remainingBytes;
  },

  reset: () => set(initialState),
}));
