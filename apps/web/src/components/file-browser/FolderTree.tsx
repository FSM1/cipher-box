/**
 * @deprecated This component is no longer used as of Phase 6.3.
 * Folder navigation is now handled via in-place navigation with ParentDirRow.
 * This file is kept for reference and will be removed in a future cleanup.
 */
import { useVaultStore } from '../../stores/vault.store';
import { useFolderStore } from '../../stores/folder.store';
import { FolderTreeNode } from './FolderTreeNode';

type FolderTreeProps = {
  /** Currently selected/active folder ID */
  currentFolderId: string;
  /** Callback when folder is clicked */
  onNavigate: (folderId: string) => void;
  /** Callback when item is dropped on a folder (move operation) */
  onDrop?: (targetFolderId: string, dataTransfer: DataTransfer) => void;
};

/**
 * Folder tree sidebar component.
 *
 * Displays the folder hierarchy starting from the root vault folder.
 * Supports navigation via clicking and drag-drop for move operations.
 *
 * Per CONTEXT.md: Auto-collapses on mobile (CSS handles overlay mode).
 *
 * @example
 * ```tsx
 * function FileBrowser() {
 *   const { currentFolderId, navigateTo } = useFolderNavigation();
 *
 *   const handleDrop = (targetId: string, data: DataTransfer) => {
 *     const item = JSON.parse(data.getData('application/json'));
 *     moveItem(item.id, item.type, item.parentId, targetId);
 *   };
 *
 *   return (
 *     <FolderTree
 *       currentFolderId={currentFolderId}
 *       onNavigate={navigateTo}
 *       onDrop={handleDrop}
 *     />
 *   );
 * }
 * ```
 */
export function FolderTree({ currentFolderId, onNavigate, onDrop }: FolderTreeProps) {
  // Check if vault is initialized
  const isVaultReady = useVaultStore((state) => state.isInitialized);
  const rootIpnsName = useVaultStore((state) => state.rootIpnsName);

  // Check if root folder exists in folder store
  const hasRootFolder = useFolderStore((state) => !!state.folders['root']);

  // If vault not ready, show placeholder
  if (!isVaultReady || !rootIpnsName) {
    return (
      <div className="folder-tree">
        <div className="folder-tree-header">
          <h3 className="folder-tree-title">Folders</h3>
        </div>
        <div className="folder-tree-content">
          <p className="folder-tree-placeholder">Vault not initialized</p>
        </div>
      </div>
    );
  }

  // If root folder not yet in store, show loading
  if (!hasRootFolder) {
    return (
      <div className="folder-tree">
        <div className="folder-tree-header">
          <h3 className="folder-tree-title">Folders</h3>
        </div>
        <div className="folder-tree-content">
          <p className="folder-tree-placeholder">Loading folders...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="folder-tree">
      <div className="folder-tree-header">
        <h3 className="folder-tree-title">Folders</h3>
      </div>
      <div className="folder-tree-content">
        <FolderTreeNode
          folderId="root"
          level={0}
          currentFolderId={currentFolderId}
          onNavigate={onNavigate}
          onDrop={onDrop}
        />
      </div>
    </div>
  );
}
