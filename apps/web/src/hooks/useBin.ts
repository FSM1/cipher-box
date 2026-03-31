import { useState, useCallback } from 'react';
import { useBinStore } from '../stores/bin.store';
import { useAuthStore } from '../stores/auth.store';
import { useVaultSettingsStore } from '../stores/vault-settings.store';
import { getSdkClient, hasSdkClient } from '../lib/sdk-provider';
import { initializeBin, purgeExpired } from '../services/bin.service';
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
   * Uses initializeBin from bin.service for initial load (populates SDK bin state
   * via useBinStore), then triggers purge as fire-and-forget.
   */
  const loadBin = useCallback(async () => {
    const auth = useAuthStore.getState();
    if (!auth.vaultKeypair) return;

    setState({ isLoading: true, error: null });
    try {
      // Initialize bin via service (sets up bin IPNS, populates store)
      await initializeBin({
        userPrivateKey: auth.vaultKeypair.privateKey,
        userPublicKey: auth.vaultKeypair.publicKey,
      });

      // Also load bin into SDK client for subsequent operations
      if (hasSdkClient()) {
        try {
          await getSdkClient().loadBin();
        } catch {
          // SDK bin load is non-blocking -- bin service already populated the store
        }
      }

      // Non-blocking: purge expired entries after loading
      const currentRetention = useBinStore.getState().retentionDays;
      void purgeExpired({
        retentionDays: currentRetention,
        userPublicKey: auth.vaultKeypair.publicKey,
        userPrivateKey: auth.vaultKeypair.privateKey,
      }).catch(() => {
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
    try {
      // Look up the target folder from the bin entry's metadata
      const binEntries = useBinStore.getState().entries;
      const entry = binEntries.find((e) => e.id === entryId);
      if (!entry) throw new Error('Bin entry not found');

      const client = getSdkClient();
      await client.restoreFromBin(entryId, entry.originalParentIpnsName);
      // SDK emits bin:updated -> store subscription updates entries
      setState({ isLoading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Failed to restore item';
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
    try {
      const binEntries = useBinStore.getState().entries;
      const client = getSdkClient();
      for (const entryId of entryIds) {
        const entry = binEntries.find((e) => e.id === entryId);
        if (!entry) continue;
        await client.restoreFromBin(entryId, entry.originalParentIpnsName);
      }
      setState({ isLoading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Failed to restore items';
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
