import { useCallback, useRef } from 'react';
import { useInterval } from './useInterval';
import { useVisibility } from './useVisibility';
import { useOnlineStatus } from './useOnlineStatus';
import { useDeviceRegistryStore } from '../stores/device-registry.store';
import { useAuthStore } from '../stores/auth.store';
import { loadRegistry } from '../services/device-registry.service';

/** Polling interval for registry changes (independent from vault sync) */
const REGISTRY_SYNC_INTERVAL_MS = 60_000; // 60 seconds per CONTEXT.md

/**
 * Polling hook for remote device registry changes.
 *
 * Runs independently from vault sync (different interval, different IPNS name).
 * Checks for remote registry changes every 60s, pausing when the tab is
 * backgrounded or the browser is offline.
 *
 * Does NOT fire an initial sync on mount -- Task 2 handles the initial load
 * via initializeOrSyncRegistry in the auth flow. This hook only handles
 * subsequent periodic checks.
 *
 * IMPORTANT (from MEMORY.md): Uses getState() inside async callbacks to
 * read fresh state, not hook selectors that capture stale closures.
 */
export function useDeviceRegistrySync(): void {
  const isVisible = useVisibility();
  const isOnline = useOnlineStatus();

  // Guard against concurrent sync runs
  const isSyncingRef = useRef(false);

  const doSync = useCallback(async () => {
    // Only sync when initialized (initial load via auth flow is complete)
    if (!useDeviceRegistryStore.getState().isInitialized) return;

    // Read fresh state for privateKey (avoid stale closures)
    const privateKey = useAuthStore.getState().vaultKeypair?.privateKey;
    if (!privateKey) return; // Not logged in

    // Skip if already syncing
    if (isSyncingRef.current) return;
    isSyncingRef.current = true;

    try {
      const result = await loadRegistry(privateKey);

      if (result) {
        const currentRegistry = useDeviceRegistryStore.getState().registry;
        const currentSeqNum = currentRegistry?.sequenceNumber ?? -1;

        // Only update if remote has a newer sequence number
        if (result.registry.sequenceNumber > currentSeqNum) {
          useDeviceRegistryStore.getState().updateRegistry(result.registry);
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Registry sync failed';
      useDeviceRegistryStore.getState().setSyncError(message);
    } finally {
      isSyncingRef.current = false;
    }
  }, []);

  // Pause polling when backgrounded or offline
  const pollDelay = isVisible && isOnline ? REGISTRY_SYNC_INTERVAL_MS : null;

  useInterval(doSync, pollDelay);
}
