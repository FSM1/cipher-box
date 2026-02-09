import { useCallback, useEffect, useRef } from 'react';
import { useInterval } from './useInterval';
import { useVisibility } from './useVisibility';
import { useOnlineStatus } from './useOnlineStatus';
import { useSyncStore } from '../stores/sync.store';
import { useVaultStore } from '../stores/vault.store';

const SYNC_INTERVAL_MS = 30000; // 30 seconds per CONTEXT.md

/**
 * Orchestrates IPNS polling for multi-device sync.
 *
 * Behavior per CONTEXT.md:
 * - Polls every 30s when tab is visible and online
 * - Pauses polling when tab is backgrounded (saves battery)
 * - Polls immediately when tab regains focus (per RESEARCH.md recommendation)
 * - Polls immediately when coming back online
 * - Updates sync store with status (syncing/success/error)
 *
 * @param onSync - Callback to execute sync logic (resolve IPNS, compare, refresh)
 */
export function useSyncPolling(onSync: () => Promise<void>): void {
  const isVisible = useVisibility();
  const isOnline = useOnlineStatus();
  const { startSync, syncSuccess, syncFailure, completeInitialSync, setOnline } = useSyncStore();
  const { rootIpnsName, isNewVault } = useVaultStore();

  // Track previous states for edge detection
  const prevOnline = useRef(isOnline);
  const prevVisible = useRef(isVisible);

  // Guard against concurrent sync runs - multiple triggers can occur (interval + visibility + reconnect)
  const isSyncingRef = useRef(false);

  // Track whether initial sync has been attempted
  const initialSyncFired = useRef(false);

  // For new vaults, skip the syncing state — there's nothing to sync
  useEffect(() => {
    if (isNewVault && !useSyncStore.getState().initialSyncComplete) {
      completeInitialSync();
    }
  }, [isNewVault, completeInitialSync]);

  // Keep sync store's isOnline in sync
  useEffect(() => {
    setOnline(isOnline);
  }, [isOnline, setOnline]);

  // Wrapped sync callback that updates store state with concurrent execution guard
  const doSync = useCallback(async () => {
    if (!rootIpnsName || !isOnline) return;

    // Skip if already syncing to prevent race conditions
    if (isSyncingRef.current) return;
    isSyncingRef.current = true;

    startSync();
    try {
      await onSync();
      syncSuccess();
      // Mark initial sync complete only on success (IPNS resolved)
      if (!useSyncStore.getState().initialSyncComplete) {
        completeInitialSync();
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Sync failed';
      syncFailure(message);
      // Don't mark initial sync complete on failure — will retry
    } finally {
      isSyncingRef.current = false;
    }
  }, [rootIpnsName, isOnline, onSync, startSync, syncSuccess, syncFailure, completeInitialSync]);

  // Immediate sync on first mount — don't wait for the 30s interval
  useEffect(() => {
    if (rootIpnsName && isOnline && !initialSyncFired.current) {
      initialSyncFired.current = true;
      doSync();
    }
  }, [rootIpnsName, isOnline, doSync]);

  // Determine polling delay: null pauses, number runs
  // Per CONTEXT.md: pause when backgrounded (Claude's discretion chose pause)
  const pollDelay = isVisible && isOnline ? SYNC_INTERVAL_MS : null;

  // Regular interval polling
  useInterval(doSync, pollDelay);

  // Immediate sync on visibility regain (per RESEARCH.md recommendation)
  useEffect(() => {
    if (isVisible && !prevVisible.current && isOnline) {
      doSync();
    }
    prevVisible.current = isVisible;
  }, [isVisible, isOnline, doSync]);

  // Immediate sync on reconnect (per CONTEXT.md)
  useEffect(() => {
    if (isOnline && !prevOnline.current) {
      doSync();
    }
    prevOnline.current = isOnline;
  }, [isOnline, doSync]);
}
