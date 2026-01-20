import { create } from 'zustand';
import { vaultApi, QuotaResponse } from '../lib/api/vault';

type QuotaState = {
  usedBytes: number;
  limitBytes: number;
  remainingBytes: number;
  loading: boolean;
  error: string | null;

  fetchQuota: () => Promise<void>;
  addUsage: (bytes: number) => void;
  removeUsage: (bytes: number) => void;
  canUpload: (bytes: number) => boolean;
};

export const useQuotaStore = create<QuotaState>((set, get) => ({
  usedBytes: 0,
  limitBytes: 500 * 1024 * 1024, // 500 MiB
  remainingBytes: 500 * 1024 * 1024,
  loading: false,
  error: null,

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

  addUsage: (bytes) =>
    set((state) => ({
      usedBytes: state.usedBytes + bytes,
      remainingBytes: state.remainingBytes - bytes,
    })),

  removeUsage: (bytes) =>
    set((state) => ({
      usedBytes: Math.max(0, state.usedBytes - bytes),
      remainingBytes: Math.min(state.limitBytes, state.remainingBytes + bytes),
    })),

  canUpload: (bytes) => {
    const { remainingBytes } = get();
    return bytes <= remainingBytes;
  },
}));
