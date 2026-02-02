import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
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
  // Get folder ID from URL params - defaults to 'root' when not present
  const { folderId } = useParams<{ folderId?: string }>();
  const navigate = useNavigate();
  const currentFolderId = folderId ?? 'root';

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

  // Build breadcrumbs whenever current folder changes (memoized to avoid recreating array)
  const breadcrumbs = useMemo(
    () => buildBreadcrumbs(currentFolderId, folders, vaultState),
    [currentFolderId, folders, vaultState]
  );

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
  }, [breadcrumbs, setBreadcrumbs]);

  /**
   * Navigate to a specific folder using react-router.
   * Browser history is automatically managed.
   */
  const navigateTo = useCallback(
    (targetFolderId: string) => {
      // Navigate to URL - root folder goes to /files, others to /files/:folderId
      if (targetFolderId === 'root') {
        navigate('/files');
      } else {
        navigate(`/files/${targetFolderId}`);
      }

      // Handle folder loading state
      const targetFolder =
        targetFolderId === 'root' ? getRootFolder(vaultState, folders) : folders[targetFolderId];

      if (targetFolder && !targetFolder.isLoaded && !targetFolder.isLoading) {
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
    },
    [navigate, folders, vaultState, setFolder]
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
