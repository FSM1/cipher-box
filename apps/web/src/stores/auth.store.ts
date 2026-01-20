import { create } from 'zustand';

type TeeKeys = {
  currentEpoch: number;
  currentPublicKey: string;
  previousEpoch: number | null;
  previousPublicKey: string | null;
};

type AuthState = {
  accessToken: string | null;
  isAuthenticated: boolean;
  lastAuthMethod: string | null;
  teeKeys: TeeKeys | null;

  setAccessToken: (token: string) => void;
  setLastAuthMethod: (method: string) => void;
  setTeeKeys: (keys: TeeKeys) => void;
  logout: () => void;
};

export const useAuthStore = create<AuthState>((set) => ({
  // State - stored in memory only, NOT localStorage (XSS prevention)
  accessToken: null,
  isAuthenticated: false,
  lastAuthMethod: null,
  teeKeys: null,

  // Actions
  setAccessToken: (token) => set({ accessToken: token, isAuthenticated: true }),
  setLastAuthMethod: (method) => set({ lastAuthMethod: method }),
  setTeeKeys: (keys) => set({ teeKeys: keys }),
  logout: () =>
    set({
      accessToken: null,
      isAuthenticated: false,
      teeKeys: null,
    }),
}));
