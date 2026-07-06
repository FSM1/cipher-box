import { create } from 'zustand';
import { type VaultSettings, DEFAULT_VAULT_SETTINGS } from '@cipherbox/sdk';

type VaultSettingsState = {
  /** Current vault settings */
  settings: VaultSettings;
  /** True after first successful load */
  isLoaded: boolean;

  // Actions
  setSettings: (settings: VaultSettings) => void;
  clearSettings: () => void;
};

/**
 * Vault settings store for managing user-configurable vault parameters.
 *
 * Holds retention period, delete behavior, versioning limits, and cooldown.
 * Populated from encrypted IPNS entry on login, cleared on logout.
 *
 * Used by:
 * - useAuth (load on login, clear on logout)
 * - useFolderMutations (delete behavior)
 * - file-metadata.service (version limits and cooldown)
 * - useBin (retention days)
 * - VaultTab (settings UI)
 */
export const useVaultSettingsStore = create<VaultSettingsState>((set) => ({
  settings: { ...DEFAULT_VAULT_SETTINGS },
  isLoaded: false,

  setSettings: (settings) => set({ settings, isLoaded: true }),
  clearSettings: () =>
    set({
      settings: { ...DEFAULT_VAULT_SETTINGS },
      isLoaded: false,
    }),
}));
