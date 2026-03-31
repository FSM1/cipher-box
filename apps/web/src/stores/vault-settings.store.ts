import { create } from 'zustand';
import { type VaultSettings, DEFAULT_VAULT_SETTINGS } from '@cipherbox/core';

type VaultSettingsState = {
  /** Current vault settings */
  settings: VaultSettings;
  /** True while loading settings from IPNS */
  isLoading: boolean;
  /** True after first successful load */
  isLoaded: boolean;
  /** True while saving settings to IPNS */
  isSaving: boolean;
  /** Last error message, null = no error */
  error: string | null;

  // Actions
  setSettings: (settings: VaultSettings) => void;
  setLoading: (loading: boolean) => void;
  setLoaded: (loaded: boolean) => void;
  setSaving: (saving: boolean) => void;
  setError: (error: string | null) => void;
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
  isLoading: false,
  isLoaded: false,
  isSaving: false,
  error: null,

  setSettings: (settings) => set({ settings, isLoaded: true, error: null }),
  setLoading: (isLoading) => set({ isLoading }),
  setLoaded: (isLoaded) => set({ isLoaded }),
  setSaving: (isSaving) => set({ isSaving }),
  setError: (error) => set({ error }),
  clearSettings: () =>
    set({
      settings: { ...DEFAULT_VAULT_SETTINGS },
      isLoading: false,
      isLoaded: false,
      isSaving: false,
      error: null,
    }),
}));
