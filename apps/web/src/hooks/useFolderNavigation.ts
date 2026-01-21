import { useState, useCallback, useEffect } from 'react';
import { useFolderStore, type FolderNode } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';

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
  navigateTo: (folderId: string) => void;
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
  if (!vaultStore.rootFolderKey || !vaultStore.rootIpnsKeypair || !vaultStore.rootIpnsName) {
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
    folderKey: vaultStore.rootFolderKey,
    ipnsPrivateKey: vaultStore.rootIpnsKeypair.privateKey,
  };
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
 *       <FolderTree currentFolderId={currentFolder?.id} onNavigate={navigateTo} />
 *       <FileList items={currentFolder?.children ?? []} />
 *     </div>
 *   );
 * }
 * ```
 */
export function useFolderNavigation(): UseFolderNavigationReturn {
  // Local state for current folder ID (default to 'root')
  const [currentFolderId, setCurrentFolderId] = useState<string>('root');
  const [isLoading, setIsLoading] = useState(false);

  // Subscribe to stores
  const folders = useFolderStore((state) => state.folders);
  const setFolder = useFolderStore((state) => state.setFolder);
  const setBreadcrumbs = useFolderStore((state) => state.setBreadcrumbs);

  // Vault state for root folder
  const rootFolderKey = useVaultStore((state) => state.rootFolderKey);
  const rootIpnsKeypair = useVaultStore((state) => state.rootIpnsKeypair);
  const rootIpnsName = useVaultStore((state) => state.rootIpnsName);

  // Get vault state snapshot for helper functions
  const vaultState = useVaultStore.getState();

  // Get current folder node
  const currentFolder =
    currentFolderId === 'root' ? getRootFolder(vaultState, folders) : folders[currentFolderId];

  // Build breadcrumbs whenever current folder changes
  const breadcrumbs = buildBreadcrumbs(currentFolderId, folders, vaultState);

  // Initialize root folder in store if vault is ready but root not in store
  useEffect(() => {
    if (rootFolderKey && rootIpnsKeypair && rootIpnsName && !folders['root']) {
      const rootFolder = getRootFolder(vaultState, folders);
      if (rootFolder) {
        setFolder(rootFolder);
      }
    }
  }, [rootFolderKey, rootIpnsKeypair, rootIpnsName, folders, setFolder, vaultState]);

  // Update store breadcrumbs when local breadcrumbs change
  useEffect(() => {
    setBreadcrumbs(breadcrumbs);
  }, [currentFolderId, setBreadcrumbs, breadcrumbs]);

  /**
   * Navigate to a specific folder.
   */
  const navigateTo = useCallback(
    (folderId: string) => {
      const targetFolder =
        folderId === 'root' ? getRootFolder(vaultState, folders) : folders[folderId];

      // If folder exists and is loaded, navigate immediately
      if (targetFolder) {
        setCurrentFolderId(folderId);

        // If folder is not loaded yet, trigger loading
        // (actual IPNS resolution deferred to Phase 7)
        if (!targetFolder.isLoaded && !targetFolder.isLoading) {
          setIsLoading(true);
          // Mark folder as loading
          setFolder({ ...targetFolder, isLoading: true });

          // Simulate async load (actual implementation in Phase 7)
          // For now, mark as loaded after a brief delay
          setTimeout(() => {
            setFolder({ ...targetFolder, isLoaded: true, isLoading: false });
            setIsLoading(false);
          }, 100);
        }
      }
    },
    [folders, vaultState, setFolder]
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
