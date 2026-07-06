import { useCallback, useEffect, useRef } from 'react';
import { useInterval } from './useInterval';
import { useVisibility } from './useVisibility';
import { useOnlineStatus } from './useOnlineStatus';
import { useSyncStore } from '../stores/sync.store';
import { useVaultStore } from '../stores/vault.store';
import { useFolderStore } from '../stores/folder.store';
import { getSdkClient, hasSdkClient } from '../lib/sdk-provider';
import { logger } from '../lib/logger';

const SYNC_INTERVAL_MS = 30000; // 30 seconds per CONTEXT.md

/**
 * D-03 belt-and-suspenders freshness, poll leg: on every sync tick (in
 * addition to whatever `onSync` itself resyncs), also re-resolve the
 * currently OPEN folder via the SDK's gated `listFolder`/`ensureFolderLoaded`
 * -- never independently resolved by the web (SC#3). Layered on top of the
 * existing 30s poll so a folder left open (no navigation event to trigger
 * the nav-triggered re-resolve leg) still picks up remote changes (e.g. a
 * write from another device). Best-effort: a failure here must never fail
 * the overall sync tick.
 *
 * Exported for direct unit testing (see `__tests__/useSyncPolling.test.ts`)
 * -- a plain async function, no React render harness needed.
 */
export async function invalidateOpenFolder(): Promise<void> {
  if (!hasSdkClient()) return;
  const { currentFolderId, folders } = useFolderStore.getState();
  if (!currentFolderId) return;
  const openFolder = folders[currentFolderId];
  if (!openFolder || !openFolder.isLoaded) return;

  try {
    const client = getSdkClient();
    const [resolved, state] = await Promise.all([
      client.listFolder(openFolder.ipnsName, { forceResolve: true }),
      client.ensureFolderLoaded(openFolder.ipnsName, { forceResolve: true }),
    ]);
    const store = useFolderStore.getState();
    // Re-check: the open folder may have changed (or been removed) while
    // the above awaited.
    if (store.currentFolderId !== currentFolderId || !store.folders[currentFolderId]) return;
    store.updateFolderChildren(currentFolderId, resolved);
    if (state) {
      store.updateFolderRawChildren(currentFolderId, state.children);
      store.updateFolderSequence(currentFolderId, state.sequenceNumber);
    }
  } catch (err) {
    logger.error('[SyncPolling] Open-folder poll invalidation failed:', err);
  }
}

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
      // D-03 poll leg: keep the currently open folder live even when
      // `onSync` itself only resyncs the root (best-effort, never fails
      // the tick).
      await invalidateOpenFolder();
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
  // Skip for new vaults: there's no IPNS record to resolve yet
  useEffect(() => {
    if (rootIpnsName && isOnline && !isNewVault && !initialSyncFired.current) {
      initialSyncFired.current = true;
      doSync();
    }
  }, [rootIpnsName, isOnline, isNewVault, doSync]);

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
