import { create } from 'zustand';

/**
 * IPNS keypair for folder metadata signing.
 * Ed25519 keypair for signing IPNS records.
 */
type IpnsKeypair = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
};

type VaultState = {
  // Decrypted vault keys (memory-only) — node/v3
  /** Root folder read key (AES-256 — decrypts the root Node's sealed read-body) */
  rootReadKey: Uint8Array | null;
  /** Root folder write key (AES-256 — decrypts the root Node's sealed write-body) */
  rootWriteKey: Uint8Array | null;
  rootIpnsKeypair: IpnsKeypair | null;
  rootIpnsName: string | null;

  // Vault metadata from server
  vaultId: string | null;
  isInitialized: boolean;
  isNewVault: boolean;

  // Actions
  setVaultKeys: (keys: {
    rootReadKey: Uint8Array;
    rootWriteKey: Uint8Array;
    rootIpnsKeypair: IpnsKeypair;
    rootIpnsName: string;
    vaultId: string;
    isNewVault?: boolean;
  }) => void;
  clearVaultKeys: () => void;
};

/**
 * Vault store for managing decrypted vault keys in memory.
 *
 * Keys are set after vault initialization/retrieval:
 * 1. User logs in via Web3Auth (auth.store.ts provides user's Ed25519 keypair)
 * 2. Login flow fetches vault from backend API (GET /vault)
 * 3. If vault exists: call decryptVaultKeys(encrypted, userPrivateKey) → VaultInit
 * 4. If vault is new: call initializeVault + encryptVaultKeys + serializeVaultBlobV3
 * 5. Call vaultStore.setVaultKeys() with decrypted keys
 * 6. On logout: auth.store.ts should call vaultStore.clearVaultKeys() before clearing auth state
 *
 * SECURITY: All keys are memory-only — never persisted to localStorage/sessionStorage.
 */
export const useVaultStore = create<VaultState>((set, get) => ({
  // State
  rootReadKey: null,
  rootWriteKey: null,
  rootIpnsKeypair: null,
  rootIpnsName: null,
  vaultId: null,
  isInitialized: false,
  isNewVault: false,

  // Actions
  setVaultKeys: (keys) =>
    set({
      rootReadKey: keys.rootReadKey,
      rootWriteKey: keys.rootWriteKey,
      rootIpnsKeypair: keys.rootIpnsKeypair,
      rootIpnsName: keys.rootIpnsName,
      vaultId: keys.vaultId,
      isInitialized: true,
      isNewVault: keys.isNewVault ?? false,
    }),

  // [SECURITY: MEDIUM-02] Zero-fill sensitive key material before clearing
  clearVaultKeys: () => {
    const state = get();

    // Best-effort memory clearing — overwrite with zeros
    if (state.rootReadKey) {
      state.rootReadKey.fill(0);
    }
    if (state.rootWriteKey) {
      state.rootWriteKey.fill(0);
    }

    if (state.rootIpnsKeypair) {
      if (state.rootIpnsKeypair.privateKey) {
        state.rootIpnsKeypair.privateKey.fill(0);
      }
      if (state.rootIpnsKeypair.publicKey) {
        state.rootIpnsKeypair.publicKey.fill(0);
      }
    }

    set({
      rootReadKey: null,
      rootWriteKey: null,
      rootIpnsKeypair: null,
      rootIpnsName: null,
      vaultId: null,
      isInitialized: false,
      isNewVault: false,
    });
  },
}));
