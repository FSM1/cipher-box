import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import type { ResolvedChild, FolderState } from '@cipherbox/sdk';
import { useFolderStore, type FolderNode } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { getSdkClient } from '../lib/sdk-provider';
import { logger } from '../lib/logger';

/**
 * Breadcrumb entry for navigation.
 */
export type Breadcrumb = {
  id: string;
  name: string;
};

/**
 * Hook return type.
 */
type UseFolderNavigationReturn = {
  currentFolderId: string;
  currentFolder: FolderNode | null;
  breadcrumbs: Breadcrumb[];
  isLoading: boolean;
  navigateTo: (folderId: string) => Promise<void>;
  navigateUp: () => void;
};

/**
 * Get the root folder from vault state or folder store.
 */
function getRootFolder(
  vaultStore: ReturnType<typeof useVaultStore.getState>,
  folders: Record<string, FolderNode>
): FolderNode | null {
  // If we have an explicit root folder in the tree, use it
  const existingRoot = folders['root'];
  if (existingRoot) return existingRoot;

  // Otherwise construct from vault state
  if (!vaultStore.rootReadKey || !vaultStore.rootIpnsKeypair || !vaultStore.rootIpnsName) {
    return null;
  }

  return {
    id: 'root',
    name: 'My Vault',
    ipnsName: vaultStore.rootIpnsName,
    parentId: null,
    children: [],
    isLoaded: false,
    isLoading: false,
    sequenceNumber: 0n,
    folderKey: vaultStore.rootReadKey,
    ipnsPrivateKey: vaultStore.rootIpnsKeypair.privateKey,
  };
}

/**
 * D-03 belt-and-suspenders freshness, deterministic leg: re-resolve a
 * folder's `ResolvedChild[]` display listing (+ raw `SealedChildRef[]`
 * identity mirror and current sequence) via the SDK's gated
 * `listFolder`/`ensureFolderLoaded` -- the web never independently resolves
 * (SC#3). `listFolder`'s in-SDK cache (keyed by ipnsName+sequenceNumber,
 * 68.2-02) makes a call for an unchanged folder cheap. No-ops if the folder
 * has since been removed from the store (navigated away / deleted).
 */
async function refreshFolderListing(ipnsName: string, folderId: string): Promise<void> {
  const client = getSdkClient();
  const [resolved, state] = await Promise.all([
    client.listFolder(ipnsName, { forceResolve: true }),
    client.ensureFolderLoaded(ipnsName, { forceResolve: true }),
  ]);
  const store = useFolderStore.getState();
  if (!store.folders[folderId]) return;
  store.updateFolderChildren(folderId, resolved);
  if (state) {
    store.updateFolderRawChildren(folderId, state.children);
    store.updateFolderSequence(folderId, state.sequenceNumber);
  }
}

/**
 * Build breadcrumb trail from current folder to root.
 */
function buildBreadcrumbs(
  folderId: string,
  folders: Record<string, FolderNode>,
  vaultStore: ReturnType<typeof useVaultStore.getState>
): Breadcrumb[] {
  const breadcrumbs: Breadcrumb[] = [];
  let currentId: string | null = folderId;

  while (currentId) {
    const currentFolder: FolderNode | null =
      currentId === 'root' ? getRootFolder(vaultStore, folders) : folders[currentId];
    if (!currentFolder) break;

    breadcrumbs.unshift({ id: currentFolder.id, name: currentFolder.name });
    currentId = currentFolder.parentId;
  }

  return breadcrumbs;
}

/**
 * Hook for managing folder navigation state.
 *
 * Provides current folder, breadcrumb trail, and navigation functions.
 * Integrates with folder store for folder tree state and vault store
 * for root folder keys.
 *
 * @example
 * ```tsx
 * function FileBrowser() {
 *   const { currentFolder, breadcrumbs, navigateTo, navigateUp } = useFolderNavigation();
 *
 *   return (
 *     <div>
 *       <Breadcrumbs items={breadcrumbs} onNavigate={navigateTo} />
 *       <FileList items={currentFolder?.children ?? []} />
 *     </div>
 *   );
 * }
 * ```
 */
export function useFolderNavigation(): UseFolderNavigationReturn {
  // Get folder ID from URL params - defaults to 'root' when not present
  const { folderId } = useParams<{ folderId?: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const currentFolderId = folderId ?? 'root';

  const [isLoading, setIsLoading] = useState(false);
  // Track latest navigation target to prevent stale completions from race conditions
  const latestNavTarget = useRef<string | null>(null);
  // Track the live route pathname so async completions can detect that the user
  // has navigated away (e.g. to /bin) since the folder resolve began. The ref is
  // kept current via the effect below; navigateTo's closure captures `navigate`
  // only, so reading `location` directly would be stale by the time async runs.
  const latestPathname = useRef(location.pathname);
  useEffect(() => {
    latestPathname.current = location.pathname;
  }, [location.pathname]);

  // Subscribe to stores
  const folders = useFolderStore((state) => state.folders);
  const setFolder = useFolderStore((state) => state.setFolder);
  const setBreadcrumbs = useFolderStore((state) => state.setBreadcrumbs);

  // Vault state for root folder
  const rootReadKey = useVaultStore((state) => state.rootReadKey);
  const rootIpnsKeypair = useVaultStore((state) => state.rootIpnsKeypair);
  const rootIpnsName = useVaultStore((state) => state.rootIpnsName);

  // Get vault state snapshot for helper functions
  const vaultState = useVaultStore.getState();

  // Get current folder node
  const currentFolder =
    currentFolderId === 'root' ? getRootFolder(vaultState, folders) : folders[currentFolderId];

  // Build breadcrumbs whenever current folder changes (memoized to avoid recreating array)
  const breadcrumbs = useMemo(
    () => buildBreadcrumbs(currentFolderId, folders, vaultState),
    [currentFolderId, folders, vaultState]
  );

  // Initialize root folder in store if vault is ready but root not in store
  useEffect(() => {
    if (rootReadKey && rootIpnsKeypair && rootIpnsName && !folders['root']) {
      const rootFolder = getRootFolder(vaultState, folders);
      if (rootFolder) {
        setFolder(rootFolder);
      }
    }
  }, [rootReadKey, rootIpnsKeypair, rootIpnsName, folders, setFolder, vaultState]);

  // Update store breadcrumbs when local breadcrumbs change
  useEffect(() => {
    setBreadcrumbs(breadcrumbs);
  }, [breadcrumbs, setBreadcrumbs]);

  /**
   * Navigate to a specific folder using react-router.
   * Browser history is automatically managed.
   * Loads subfolder metadata (IPNS resolve + decrypt) if not yet loaded.
   */
  const navigateTo = useCallback(
    async (targetFolderId: string) => {
      // Track this navigation to detect stale completions from rapid clicks
      latestNavTarget.current = targetFolderId;

      // Root is always constructible from vault state — just navigate.
      // Clear any stuck loading flag: a superseded in-flight navigation's
      // finally block declines to clear isLoading once latestNavTarget moved
      // on (68.1-29: full-workflow 5.4 breadcrumb-during-load left the
      // spinner up forever).
      if (targetFolderId === 'root') {
        setIsLoading(false);
        navigate('/files');
        useFolderStore.getState().setCurrentFolder('root');
        // D-03 nav re-resolve (root leg): fire-and-forget, never blocks the
        // navigation itself -- keeps the cached view live if the underlying
        // vault root has changed since it was last loaded (e.g. another
        // device's write, or a prior session's stale cache).
        if (rootIpnsName) {
          void refreshFolderListing(rootIpnsName, 'root').catch((err) => {
            logger.error('[Nav] Background root re-resolve failed:', err);
          });
        }
        return;
      }

      // Use getState() to avoid stale Zustand closures in async callback
      const currentFolders = useFolderStore.getState().folders;
      const targetFolder = currentFolders[targetFolderId];

      // If already loaded, just navigate (clearing any superseded
      // navigation's stuck loading flag — see root fast path above), then
      // kick off the D-03 nav re-resolve in the background (deterministic
      // freshness leg — never independently resolved, always through the
      // SDK's gated listFolder/ensureFolderLoaded).
      if (targetFolder?.isLoaded) {
        setIsLoading(false);
        navigate(`/files/${targetFolderId}`);
        useFolderStore.getState().setCurrentFolder(targetFolderId);
        void refreshFolderListing(targetFolder.ipnsName, targetFolderId).catch((err) => {
          logger.error('[Nav] Background re-resolve failed:', err);
        });
        return;
      }

      // Find the child ref for this subfolder from any loaded parent's
      // resolved children (identifies by ipnsName; folderId maps to ipnsName
      // via the FolderNode's own ipnsName field).
      let folderRef: ResolvedChild | undefined;
      let parentId: string | null = null;

      for (const [fId, fNode] of Object.entries(currentFolders)) {
        if (!fNode.isLoaded) continue;
        const match = fNode.children.find((c) => c.ipnsName === targetFolderId);
        if (match) {
          folderRef = match;
          parentId = fId;
          break;
        }
      }

      if (!folderRef) {
        logger.error(
          `[Nav] Cannot load folder ${targetFolderId}: no loaded parent has a matching child ref`
        );
        return;
      }

      // Insert placeholder BEFORE navigating so the component re-render
      // finds the folder node already in the store (avoids undefined flash)
      setIsLoading(true);
      const loadingPlaceholder: FolderNode = {
        id: targetFolderId,
        name: folderRef.name,
        ipnsName: folderRef.ipnsName,
        parentId,
        children: [],
        isLoaded: false,
        isLoading: true,
        sequenceNumber: 0n,
        folderKey: new Uint8Array(0),
        ipnsPrivateKey: new Uint8Array(0),
      };
      useFolderStore.getState().setFolder(loadingPlaceholder);

      // Now navigate — the placeholder is already in the store
      navigate(`/files/${targetFolderId}`);

      try {
        // Phase 63: ensureFolderLoaded will implement read-chain navigation.
        // This stub will throw; the catch block removes the placeholder.
        // GAP-2 (68.1-13 / 68.1-22): cold-reload multi-level DFS resolves can
        // exceed the original 3x2s budget while local IPNS records propagate
        // after a burst of publishes. 8x3s is the documented low-risk
        // hardening — the latestNavTarget bail-out guards keep abandoned
        // navigations cheap.
        const MAX_RETRIES = 8;
        const RETRY_DELAY_MS = 3000;
        let state: FolderState | null = null;

        for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
          if (latestNavTarget.current !== targetFolderId) return;
          state = await getSdkClient().ensureFolderLoaded(folderRef.ipnsName, {
            forceResolve: true,
          });
          if (state) break;
          if (attempt === MAX_RETRIES) break;
          // IPNS not propagated yet — wait and retry
          await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
        }

        // Re-check guard after all awaits (user may have navigated away mid-retry)
        if (latestNavTarget.current !== targetFolderId) return;

        if (!state) {
          throw new Error('Folder not loaded — IPNS propagation timed out');
        }

        // D-03 nav re-resolve (deterministic freshness leg): resolve the
        // display listing through the SDK's gated `listFolder` (SDK-cached
        // by ipnsName+sequenceNumber, 68.2-02) BEFORE the FolderNode lands
        // in the store, so kind/size/modifiedAt are pre-resolved on first
        // render (no extra re-render, no web-side resolve, SC#3).
        const resolvedChildren = await getSdkClient().listFolder(folderRef.ipnsName, {
          forceResolve: true,
        });

        // Re-check the stale-completion guard again — listFolder awaited,
        // so the user may have navigated away while it was in flight.
        if (latestNavTarget.current !== targetFolderId) return;

        // Map FolderState -> FolderNode.
        // Folder identity is intentionally keyed by ipnsName here (matching
        // the `c.ipnsName === targetFolderId` lookup above and the route
        // param convention), NOT re-keyed to Node.id. A prior UUID-keying
        // attempt caused an orphaned-store-entry bug (68.1/68.2-09) -- do
        // not "fix" this to `id: node.id`.
        const folderNode: FolderNode = {
          id: targetFolderId,
          name: folderRef.name,
          ipnsName: folderRef.ipnsName,
          parentId,
          children: resolvedChildren,
          rawChildren: state.children,
          isLoaded: true,
          isLoading: false,
          sequenceNumber: state.sequenceNumber,
          folderKey: new Uint8Array(state.folderKey),
          ipnsPrivateKey: new Uint8Array(state.ipnsKeypair.privateKey),
        };

        useFolderStore.getState().setFolder(folderNode);
        useFolderStore.getState().setCurrentFolder(targetFolderId);
      } catch (err) {
        logger.error('[Nav] Failed to load subfolder:', err);
        // Only clean up if this is still the latest navigation
        if (latestNavTarget.current !== targetFolderId) return;
        // Remove the loading placeholder and navigate back to parent.
        useFolderStore.getState().removeFolder(targetFolderId);
        setIsLoading(false);
        if (latestPathname.current !== `/files/${targetFolderId}`) return;
        latestNavTarget.current = parentId ?? 'root';
        if (parentId) {
          navigate(`/files/${parentId}`);
        } else {
          navigate('/files');
        }
      } finally {
        // Only clear loading if this is still the latest navigation
        if (latestNavTarget.current === targetFolderId) {
          setIsLoading(false);
        }
      }
    },
    [navigate, rootIpnsName]
  );

  /**
   * Navigate up to parent folder.
   */
  const navigateUp = useCallback(() => {
    if (currentFolder?.parentId) {
      navigateTo(currentFolder.parentId);
    } else if (currentFolderId !== 'root') {
      navigateTo('root');
    }
  }, [currentFolder, currentFolderId, navigateTo]);

  return {
    currentFolderId,
    currentFolder,
    breadcrumbs,
    isLoading,
    navigateTo,
    navigateUp,
  };
}
