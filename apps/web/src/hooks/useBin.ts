import { useState, useCallback } from 'react';
import { useBinStore } from '../stores/bin.store';
import { useRestoreStore } from '../stores/restore.store';
import { useVaultSettingsStore } from '../stores/vault-settings.store';
import { getSdkClient, hasSdkClient } from '../lib/sdk-provider';
import type { BinEntry } from '@cipherbox/core';
import { logger } from '../lib/logger';

/**
 * React hook for recycle bin operations.
 *
 * Delegates to CipherBoxClient SDK methods for bin CRUD operations.
 * The SDK handles bin metadata, IPNS publishing, and event emission.
 * Loading/error state and purge logic remain in the hook.
 */
export function useBin() {
  const [state, setState] = useState<{ isLoading: boolean; error: string | null }>({
    isLoading: false,
    error: null,
  });

  const entries = useBinStore((s) => s.entries);
  const isLoaded = useBinStore((s) => s.isLoaded);
  const retentionDays = useVaultSettingsStore((s) => s.settings.recycleBinRetentionDays);

  /**
   * Load bin metadata from IPNS and trigger auto-purge of expired entries.
   *
   * Uses CipherBoxClient.loadBin() to load bin from IPNS and populate
   * the SDK bin state. The SDK emits bin:updated events which the store
   * subscription handles.
   */
  const loadBin = useCallback(async () => {
    if (!hasSdkClient()) return;

    setState({ isLoading: true, error: null });
    try {
      // Load bin via SDK client (handles IPNS resolve, decrypt, auto-repair)
      const binState = await getSdkClient().loadBin();

      // Update Zustand store from SDK-returned state
      const binStore = useBinStore.getState();
      binStore.setBinIpnsName(binState.ipnsName);
      binStore.setEntries(binState.entries, binState.sequenceNumber);

      // Non-blocking: purge expired entries after loading
      // Use vault settings store as single source of truth for retention
      const currentRetention = useVaultSettingsStore.getState().settings.recycleBinRetentionDays;
      void getSdkClient()
        .purgeExpired(currentRetention)
        .catch(() => {
          logger.error('[useBin] Auto-purge failed (non-blocking)');
        });

      setState({ isLoading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Failed to load bin';
      setState({ isLoading: false, error });
    }
  }, []);

  /**
   * Restore a single bin entry to its original folder via SDK.
   */
  const restore = useCallback(async (entryId: string) => {
    setState({ isLoading: true, error: null });
    const restoreStore = useRestoreStore.getState();
    try {
      // Look up the target folder from the bin entry's metadata
      const binEntries = useBinStore.getState().entries;
      const entry = binEntries.find((e) => e.id === entryId);
      if (!entry) throw new Error('Bin entry not found');

      // Metadata-only status affordance (D-05) — restore has no byte stream.
      restoreStore.startRestore(entry.name);
      const client = getSdkClient();
      await client.restoreFromBin(entryId, entry.originalParentIpnsName);
      // SDK emits bin:updated -> store subscription updates entries
      restoreStore.setRestoreSuccess();
      setState({ isLoading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Failed to restore item';
      restoreStore.setRestoreError(error);
      setState({ isLoading: false, error });
      throw err;
    }
  }, []);

  /**
   * Permanently delete a single bin entry via SDK.
   */
  const permanentDelete = useCallback(async (entryId: string) => {
    setState({ isLoading: true, error: null });
    try {
      const client = getSdkClient();
      await client.permanentDelete(entryId);
      // SDK emits bin:updated -> store subscription updates entries
      setState({ isLoading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Failed to permanently delete';
      setState({ isLoading: false, error });
      throw err;
    }
  }, []);

  /**
   * Empty all bin entries permanently via SDK.
   */
  const emptyAll = useCallback(async () => {
    setState({ isLoading: true, error: null });
    try {
      const client = getSdkClient();
      await client.emptyBin();
      // SDK emits bin:updated with empty entries -> store subscription updates
      setState({ isLoading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Failed to empty bin';
      setState({ isLoading: false, error });
      throw err;
    }
  }, []);

  /**
   * Restore multiple bin entries via SDK.
   */
  const restoreMultiple = useCallback(async (entryIds: string[]) => {
    setState({ isLoading: true, error: null });
    const restoreStore = useRestoreStore.getState();
    try {
      const binEntries = useBinStore.getState().entries;
      const client = getSdkClient();
      for (const entryId of entryIds) {
        const entry = binEntries.find((e) => e.id === entryId);
        if (!entry) continue;
        // Drive the status affordance once per entry (D-05) so the bin UI
        // reflects each in-flight restore.
        restoreStore.startRestore(entry.name);
        await client.restoreFromBin(entryId, entry.originalParentIpnsName);
      }
      restoreStore.setRestoreSuccess();
      setState({ isLoading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Failed to restore items';
      restoreStore.setRestoreError(error);
      setState({ isLoading: false, error });
      throw err;
    }
  }, []);

  /**
   * Permanently delete multiple bin entries via SDK.
   */
  const permanentDeleteMultiple = useCallback(async (entryIds: string[]) => {
    setState({ isLoading: true, error: null });
    try {
      const client = getSdkClient();
      for (const entryId of entryIds) {
        await client.permanentDelete(entryId);
      }
      setState({ isLoading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Failed to permanently delete items';
      setState({ isLoading: false, error });
      throw err;
    }
  }, []);

  /**
   * Calculate days remaining before a bin entry is auto-purged.
   */
  const daysRemaining = useCallback(
    (entry: BinEntry): number => {
      const elapsed = Date.now() - entry.deletedAt;
      const retentionMs = retentionDays * 24 * 60 * 60 * 1000;
      return Math.max(0, Math.ceil((retentionMs - elapsed) / (24 * 60 * 60 * 1000)));
    },
    [retentionDays]
  );

  return {
    ...state,
    entries,
    isLoaded,
    retentionDays,
    daysRemaining,
    loadBin,
    restore,
    permanentDelete,
    emptyAll,
    restoreMultiple,
    permanentDeleteMultiple,
  };
}
