import { create } from 'zustand';

type TeeKeys = {
  currentEpoch: number;
  currentPublicKey: string;
  previousEpoch: number | null;
  previousPublicKey: string | null;
};

/**
 * User's secp256k1 vault keypair from Core Kit TSS export.
 * Memory-only, never persisted.
 */
type VaultKeypair = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
};

type AuthState = {
  accessToken: string | null;
  isAuthenticated: boolean;
  lastAuthMethod: string | null;
  userEmail: string | null;
  teeKeys: TeeKeys | null;

  /** User's vault keypair (memory-only, from Core Kit TSS export) */
  vaultKeypair: VaultKeypair | null;

  /** Pending auth info for REQUIRED_SHARE flow (shared across hook instances) */
  pendingCipherboxJwt: string | null;
  pendingAuthMethod: string | null;

  setAccessToken: (token: string) => void;
  setLastAuthMethod: (method: string) => void;
  setUserEmail: (email: string) => void;
  setTeeKeys: (keys: TeeKeys) => void;
  setVaultKeypair: (keypair: VaultKeypair) => void;
  setPendingAuth: (jwt: string | null, method: string | null) => void;
  logout: () => void;
};

export const useAuthStore = create<AuthState>((set, get) => ({
  // State - stored in memory only, NOT localStorage (XSS prevention)
  accessToken: null,
  isAuthenticated: false,
  lastAuthMethod: null,
  userEmail: null,
  teeKeys: null,

  /** User's vault keypair (memory-only) */
  vaultKeypair: null,

  /** Pending auth for REQUIRED_SHARE flow */
  pendingCipherboxJwt: null,
  pendingAuthMethod: null,

  // Actions
  setAccessToken: (token) => set({ accessToken: token, isAuthenticated: true }),
  setLastAuthMethod: (method) => set({ lastAuthMethod: method }),
  setUserEmail: (email) => set({ userEmail: email }),
  setTeeKeys: (keys) => set({ teeKeys: keys }),

  /** Store vault keypair from Core Kit TSS export */
  setVaultKeypair: (keypair) => set({ vaultKeypair: keypair }),

  /** Store pending auth info for REQUIRED_SHARE completion */
  setPendingAuth: (jwt, method) => set({ pendingCipherboxJwt: jwt, pendingAuthMethod: method }),

  logout: () => {
    // [SECURITY: MEDIUM-02] Zero-fill sensitive key material before clearing
    const state = get();
    if (state.vaultKeypair) {
      if (state.vaultKeypair.privateKey) {
        state.vaultKeypair.privateKey.fill(0);
      }
      if (state.vaultKeypair.publicKey) {
        state.vaultKeypair.publicKey.fill(0);
      }
    }

    set({
      accessToken: null,
      isAuthenticated: false,
      userEmail: null,
      teeKeys: null,
      vaultKeypair: null,
      pendingCipherboxJwt: null,
      pendingAuthMethod: null,
    });
  },
}));
