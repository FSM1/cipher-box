import { useState, useCallback, useEffect, useRef } from 'react';
import { useFolderStore } from '../stores/folder.store';
import { useAuthStore } from '../stores/auth.store';
import { searchIndexService, type SearchResult } from '../services/search-index.service';

// ---------------------------------------------------------------------------
// Module-level callback for triggering index rebuild from outside React tree
// ---------------------------------------------------------------------------

let _rebuildCallback: (() => void) | null = null;

export function registerRebuildCallback(cb: () => void): void {
  _rebuildCallback = cb;
}

export function triggerSearchIndexRebuild(): void {
  _rebuildCallback?.();
}

// ---------------------------------------------------------------------------
// useSearch hook
// ---------------------------------------------------------------------------

/**
 * React hook bridging SearchIndexService with UI state.
 *
 * Manages the search lifecycle: opening/closing the palette, building/loading
 * the index, querying with debounce, and persisting encrypted state.
 *
 * Global keyboard shortcut Cmd/Ctrl+K toggles the palette.
 * Index auto-clears on logout via auth state watcher.
 */
export function useSearch() {
  // State
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [isIndexReady, setIsIndexReady] = useState(false);
  const [isBuilding, setIsBuilding] = useState(false);

  // Refs
  const hasLoadedFromDb = useRef(false);
  const buildingRef = useRef(false);
  const cancelledRef = useRef(false);

  // Store access
  const vaultKeypair = useAuthStore((s) => s.vaultKeypair);
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const prevAuth = useRef(isAuthenticated);

  // Open the palette
  const open = useCallback(() => setIsOpen(true), []);
  const close = useCallback(() => {
    setIsOpen(false);
    setQuery('');
    setResults([]);
  }, []);
  const toggle = useCallback(() => {
    setIsOpen((prev) => {
      if (prev) {
        setQuery('');
        setResults([]);
      }
      return !prev;
    });
  }, []);

  // Global keyboard shortcut: Cmd/Ctrl+K
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        toggle();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [toggle]);

  // Build/refresh index every time the palette opens.
  // On cold start (empty index, no prior DB load), try loading from encrypted
  // IndexedDB first. Otherwise, always rebuild from the current folder store
  // to ensure freshness (files may have been uploaded/deleted since last open).
  useEffect(() => {
    if (!isOpen) return;
    if (!vaultKeypair) return;
    if (buildingRef.current) return;

    // If the index already has data (e.g. from a prior sync-triggered rebuild),
    // mark ready immediately so the user can search the existing index while
    // we rebuild with the latest folder state.
    if (!searchIndexService.isEmpty) {
      setIsIndexReady(true);
    }

    cancelledRef.current = false;

    const init = async () => {
      buildingRef.current = true;
      setIsBuilding(true);
      try {
        // Cold start: try loading from encrypted IndexedDB when index is empty
        if (!hasLoadedFromDb.current && searchIndexService.isEmpty) {
          const loaded = await searchIndexService.loadEncrypted(vaultKeypair.privateKey);
          if (cancelledRef.current) return;
          hasLoadedFromDb.current = true;
          if (loaded && !searchIndexService.isEmpty) {
            setIsIndexReady(true);
            return;
          }
        }

        // Build fresh from current folder store state
        const currentFolders = useFolderStore.getState().folders;
        searchIndexService.buildFromFolderTree(currentFolders);
        if (cancelledRef.current) return;
        setIsIndexReady(true);

        // Persist encrypted (fire-and-forget)
        searchIndexService.persistEncrypted(vaultKeypair.privateKey).catch((err) => {
          console.warn('[search] Failed to persist index:', err);
        });
      } catch (err) {
        console.error('[search] Failed to initialize index:', err);
        if (cancelledRef.current) return;
        // Still mark ready -- search works in-memory even if persistence fails
        setIsIndexReady(true);
      } finally {
        setIsBuilding(false);
        buildingRef.current = false;
      }
    };
    init();
  }, [isOpen, vaultKeypair]);

  // Search with debounce (150ms)
  useEffect(() => {
    if (!isOpen || !isIndexReady) return;
    if (!query.trim()) {
      setResults([]);
      return;
    }

    const timer = setTimeout(() => {
      const searchResults = searchIndexService.search(query.trim());
      setResults(searchResults);
    }, 150);

    return () => clearTimeout(timer);
  }, [query, isOpen, isIndexReady]);

  // Rebuild index method (called after sync detects changes)
  const rebuildIndex = useCallback(() => {
    if (!vaultKeypair) return;
    const currentFolders = useFolderStore.getState().folders;
    searchIndexService.buildFromFolderTree(currentFolders);
    setIsIndexReady(true);

    // Re-persist (fire-and-forget)
    searchIndexService.persistEncrypted(vaultKeypair.privateKey).catch((err) => {
      console.warn('[search] Failed to persist index after rebuild:', err);
    });
  }, [vaultKeypair]);

  // Register rebuild callback so FileBrowser can trigger it
  useEffect(() => {
    registerRebuildCallback(rebuildIndex);
    return () => {
      registerRebuildCallback(() => {});
    };
  }, [rebuildIndex]);

  // Clear index (called on logout).
  // Sets cancelledRef to abort any in-flight init() that may be suspended
  // at an await, preventing stale state writes and post-logout persistence.
  const clearIndex = useCallback(async () => {
    cancelledRef.current = true;
    try {
      await searchIndexService.clear();
    } catch (err) {
      console.warn('[search] Failed to clear index:', err);
    }
    setIsIndexReady(false);
    hasLoadedFromDb.current = false;
    buildingRef.current = false;
    setIsOpen(false);
    setQuery('');
    setResults([]);
  }, []);

  // Auto-clear on logout: when isAuthenticated transitions true -> false
  useEffect(() => {
    if (prevAuth.current && !isAuthenticated) {
      clearIndex();
    }
    prevAuth.current = isAuthenticated;
  }, [isAuthenticated, clearIndex]);

  return {
    isOpen,
    query,
    setQuery,
    results,
    isIndexReady,
    isBuilding,
    open,
    close,
    toggle,
    rebuildIndex,
    clearIndex,
    resultCount: results.length,
  };
}

export type { SearchResult };
