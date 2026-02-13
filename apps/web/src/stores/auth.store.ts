import { create } from 'zustand';

type TeeKeys = {
  currentEpoch: number;
  currentPublicKey: string;
  previousEpoch: number | null;
  previousPublicKey: string | null;
};

/**
 * Derived keypair for external wallet users (ADR-001)
 * These keys are memory-only and never persisted to storage.
 */
type DerivedKeypair = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
};

type AuthState = {
  accessToken: string | null;
  isAuthenticated: boolean;
  lastAuthMethod: string | null;
  userEmail: string | null;
  teeKeys: TeeKeys | null;

  // ADR-001: Derived keypair for external wallets (memory-only)
  derivedKeypair: DerivedKeypair | null;
  isExternalWallet: boolean;

  setAccessToken: (token: string) => void;
  setLastAuthMethod: (method: string) => void;
  setUserEmail: (email: string) => void;
  setTeeKeys: (keys: TeeKeys) => void;
  setDerivedKeypair: (keypair: DerivedKeypair) => void;
  setIsExternalWallet: (isExternal: boolean) => void;
  clearDerivedKeypair: () => void;
  logout: () => void;
};

export const useAuthStore = create<AuthState>((set, get) => ({
  // State - stored in memory only, NOT localStorage (XSS prevention)
  accessToken: null,
  isAuthenticated: false,
  lastAuthMethod: null,
  userEmail: localStorage.getItem('cipherbox:userEmail'),
  teeKeys: null,

  // ADR-001: Derived keypair state (memory-only)
  derivedKeypair: null,
  isExternalWallet: false,

  // Actions
  setAccessToken: (token) => set({ accessToken: token, isAuthenticated: true }),
  setLastAuthMethod: (method) => set({ lastAuthMethod: method }),
  setUserEmail: (email) => {
    localStorage.setItem('cipherbox:userEmail', email);
    set({ userEmail: email });
  },
  setTeeKeys: (keys) => set({ teeKeys: keys }),

  // ADR-001: Set derived keypair for external wallet users
  setDerivedKeypair: (keypair) => set({ derivedKeypair: keypair }),
  setIsExternalWallet: (isExternal) => set({ isExternalWallet: isExternal }),

  // ADR-001: Clear derived keypair with best-effort memory clearing
  // [SECURITY: MEDIUM-02] Zero-fill sensitive key material before clearing
  clearDerivedKeypair: () => {
    const state = get();
    if (state.derivedKeypair) {
      // Best-effort memory clearing - overwrite with zeros
      if (state.derivedKeypair.privateKey) {
        state.derivedKeypair.privateKey.fill(0);
      }
      if (state.derivedKeypair.publicKey) {
        state.derivedKeypair.publicKey.fill(0);
      }
    }
    set({ derivedKeypair: null });
  },

  logout: () => {
    // Clear derived keypair with memory clearing before logout
    const state = get();
    if (state.derivedKeypair) {
      if (state.derivedKeypair.privateKey) {
        state.derivedKeypair.privateKey.fill(0);
      }
      if (state.derivedKeypair.publicKey) {
        state.derivedKeypair.publicKey.fill(0);
      }
    }

    localStorage.removeItem('cipherbox:userEmail');
    set({
      accessToken: null,
      isAuthenticated: false,
      userEmail: null,
      teeKeys: null,
      derivedKeypair: null,
      isExternalWallet: false,
    });
  },
}));
