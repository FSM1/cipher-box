import { create } from 'zustand';
import type { DeviceRegistry } from '@cipherbox/crypto';

type DeviceRegistryState = {
  /** The decrypted device registry */
  registry: DeviceRegistry | null;
  /** This device's ID for highlighting in UI */
  currentDeviceId: string | null;
  /** IPNS name for the registry (display/debug) */
  registryIpnsName: string | null;
  /** Unix ms of last successful sync */
  lastSyncedAt: number | null;
  /** Last error message, null = no error */
  syncError: string | null;
  /** True after first successful load/create */
  isInitialized: boolean;

  // Actions
  setRegistry: (registry: DeviceRegistry, ipnsName: string, deviceId: string) => void;
  updateRegistry: (registry: DeviceRegistry) => void;
  setSyncError: (error: string) => void;
  clearRegistry: () => void;
};

/**
 * Device registry store for managing encrypted device registry state.
 *
 * Tracks the registry (list of authenticated devices), current device ID,
 * IPNS name, sync status, and initialization state. No sensitive key material
 * is stored here (registry contains only hex-encoded public keys and metadata),
 * but state is still zeroed on clear for clean lifecycle.
 *
 * Used by:
 * - useAuth (sets registry after login, clears on logout)
 * - useDeviceRegistrySync (updates registry on polling)
 * - Future Phase 12.4 device approval UI
 */
export const useDeviceRegistryStore = create<DeviceRegistryState>((set) => ({
  // State
  registry: null,
  currentDeviceId: null,
  registryIpnsName: null,
  lastSyncedAt: null,
  syncError: null,
  isInitialized: false,

  // Actions
  setRegistry: (registry, ipnsName, deviceId) =>
    set({
      registry,
      registryIpnsName: ipnsName,
      currentDeviceId: deviceId,
      syncError: null,
      isInitialized: true,
      lastSyncedAt: Date.now(),
    }),

  updateRegistry: (registry) =>
    set({
      registry,
      lastSyncedAt: Date.now(),
    }),

  setSyncError: (error) =>
    set({
      syncError: error,
    }),

  clearRegistry: () =>
    set({
      registry: null,
      currentDeviceId: null,
      registryIpnsName: null,
      lastSyncedAt: null,
      syncError: null,
      isInitialized: false,
    }),
}));
