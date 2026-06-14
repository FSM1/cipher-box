import { create } from 'zustand';
import { vaultApi, QuotaResponse } from '../lib/api/vault';

const DEFAULT_LIMIT_BYTES = 500 * 1024 * 1024; // 500 MiB

const initialState = {
  usedBytes: 0,
  limitBytes: DEFAULT_LIMIT_BYTES,
  remainingBytes: DEFAULT_LIMIT_BYTES,
  advisory: false,
  loading: false,
  error: null as string | null,
};

// Session version guard: incremented on reset() so in-flight fetchQuota()
// responses are discarded if they resolve after logout/reset.
let quotaSessionVersion = 0;

type QuotaState = typeof initialState & {
  // Resolves true when the quota was refreshed (or the response was discarded as
  // stale after a session reset), false when the underlying fetch failed. Never
  // rejects, so fire-and-forget callers can branch on the result without a catch.
  fetchQuota: () => Promise<boolean>;
  removeUsage: (bytes: number) => void;
  canUpload: (bytes: number) => boolean;
  reset: () => void;
};

export const useQuotaStore = create<QuotaState>((set, get) => ({
  ...initialState,

  fetchQuota: async () => {
    const requestVersion = quotaSessionVersion;
    set({ loading: true, error: null });
    try {
      const quota: QuotaResponse = await vaultApi.getQuota();
      if (requestVersion !== quotaSessionVersion) return true;
      set({
        usedBytes: quota.usedBytes,
        limitBytes: quota.limitBytes,
        remainingBytes: quota.remainingBytes,
        advisory: quota.advisory ?? false,
        loading: false,
      });
      return true;
    } catch {
      // Stale response after a session reset: not a real failure, don't signal one.
      if (requestVersion !== quotaSessionVersion) return true;
      set({ error: 'Failed to fetch quota', loading: false });
      return false;
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

  reset: () => {
    quotaSessionVersion += 1;
    set(initialState);
  },
}));
