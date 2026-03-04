import { useState, useCallback } from 'react';
import { useBinStore } from '../stores/bin.store';
import { useAuthStore } from '../stores/auth.store';
import {
  initializeBin,
  restoreFromBin,
  permanentlyDelete,
  emptyBin,
  purgeExpired,
} from '../services/bin.service';
import type { BinEntry } from '@cipherbox/crypto';

/**
 * React hook for recycle bin operations.
 *
 * Wraps bin service functions with loading/error state management.
 * Provides single-item and batch operations for restore and permanent delete.
 */
export function useBin() {
  const [state, setState] = useState<{ isLoading: boolean; error: string | null }>({
    isLoading: false,
    error: null,
  });

  const entries = useBinStore((s) => s.entries);
  const isLoaded = useBinStore((s) => s.isLoaded);
  const retentionDays = useBinStore((s) => s.retentionDays);

  /**
   * Load bin metadata from IPNS and trigger auto-purge of expired entries.
   */
  const loadBin = useCallback(async () => {
    const auth = useAuthStore.getState();
    if (!auth.vaultKeypair) return;

    setState({ isLoading: true, error: null });
    try {
      await initializeBin({
        userPrivateKey: auth.vaultKeypair.privateKey,
        userPublicKey: auth.vaultKeypair.publicKey,
      });

      // Non-blocking: purge expired entries after loading
      const currentRetention = useBinStore.getState().retentionDays;
      void purgeExpired({
        retentionDays: currentRetention,
        userPublicKey: auth.vaultKeypair.publicKey,
        userPrivateKey: auth.vaultKeypair.privateKey,
      }).catch((err) => {
        console.error('[useBin] Auto-purge failed (non-blocking):', err);
      });

      setState({ isLoading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Failed to load bin';
      setState({ isLoading: false, error });
    }
  }, []);

  /**
   * Restore a single bin entry to its original folder.
   */
  const restore = useCallback(async (entryId: string) => {
    const auth = useAuthStore.getState();
    if (!auth.vaultKeypair) throw new Error('Not authenticated');

    setState({ isLoading: true, error: null });
    try {
      await restoreFromBin({
        entryId,
        userPublicKey: auth.vaultKeypair.publicKey,
        userPrivateKey: auth.vaultKeypair.privateKey,
      });
      setState({ isLoading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Failed to restore item';
      setState({ isLoading: false, error });
      throw err;
    }
  }, []);

  /**
   * Permanently delete a single bin entry (unpin CIDs, update quota).
   */
  const permanentDelete = useCallback(async (entryId: string) => {
    const auth = useAuthStore.getState();
    if (!auth.vaultKeypair) throw new Error('Not authenticated');

    setState({ isLoading: true, error: null });
    try {
      await permanentlyDelete({
        entryId,
        userPublicKey: auth.vaultKeypair.publicKey,
        userPrivateKey: auth.vaultKeypair.privateKey,
      });
      setState({ isLoading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Failed to permanently delete';
      setState({ isLoading: false, error });
      throw err;
    }
  }, []);

  /**
   * Empty all bin entries permanently.
   */
  const emptyAll = useCallback(async () => {
    const auth = useAuthStore.getState();
    if (!auth.vaultKeypair) throw new Error('Not authenticated');

    setState({ isLoading: true, error: null });
    try {
      await emptyBin({
        userPublicKey: auth.vaultKeypair.publicKey,
        userPrivateKey: auth.vaultKeypair.privateKey,
      });
      setState({ isLoading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Failed to empty bin';
      setState({ isLoading: false, error });
      throw err;
    }
  }, []);

  /**
   * Restore multiple bin entries.
   */
  const restoreMultiple = useCallback(async (entryIds: string[]) => {
    const auth = useAuthStore.getState();
    if (!auth.vaultKeypair) throw new Error('Not authenticated');

    setState({ isLoading: true, error: null });
    try {
      for (const entryId of entryIds) {
        await restoreFromBin({
          entryId,
          userPublicKey: auth.vaultKeypair.publicKey,
          userPrivateKey: auth.vaultKeypair.privateKey,
        });
      }
      setState({ isLoading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Failed to restore items';
      setState({ isLoading: false, error });
      throw err;
    }
  }, []);

  /**
   * Permanently delete multiple bin entries.
   */
  const permanentDeleteMultiple = useCallback(async (entryIds: string[]) => {
    const auth = useAuthStore.getState();
    if (!auth.vaultKeypair) throw new Error('Not authenticated');

    setState({ isLoading: true, error: null });
    try {
      for (const entryId of entryIds) {
        await permanentlyDelete({
          entryId,
          userPublicKey: auth.vaultKeypair.publicKey,
          userPrivateKey: auth.vaultKeypair.privateKey,
        });
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
