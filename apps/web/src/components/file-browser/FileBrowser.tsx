import { useState, useCallback, type DragEvent, type MouseEvent } from 'react';
import type { FolderChild } from '@cipherbox/crypto';
import { useFolderNavigation } from '../../hooks/useFolderNavigation';
import { FolderTree } from './FolderTree';
import { FileList } from './FileList';
import { EmptyState } from './EmptyState';

/**
 * Main file browser container component.
 *
 * Orchestrates the sidebar folder tree and main file list area.
 * Manages selection state and provides context menu / drag handlers.
 *
 * Layout:
 * - Left sidebar: FolderTree for navigation
 * - Main area: FileList or EmptyState based on folder contents
 *
 * @example
 * ```tsx
 * function Dashboard() {
 *   return (
 *     <main className="dashboard-main">
 *       <FileBrowser />
 *     </main>
 *   );
 * }
 * ```
 */
export function FileBrowser() {
  // Navigation state from hook
  const { currentFolderId, currentFolder, isLoading, navigateTo } = useFolderNavigation();

  // Selection state (single selection per CONTEXT.md)
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);

  // Clear selection when navigating to a new folder
  const handleNavigate = useCallback(
    (folderId: string) => {
      setSelectedItemId(null);
      navigateTo(folderId);
    },
    [navigateTo]
  );

  // Handle item selection
  const handleSelect = useCallback((itemId: string) => {
    setSelectedItemId(itemId);
  }, []);

  // Context menu handler (placeholder - implemented in Plan 03)
  const handleContextMenu = useCallback((event: MouseEvent, item: FolderChild) => {
    event.preventDefault();
    // TODO: Implement context menu in Plan 03
    console.log('Context menu for:', item.name, item.type);
  }, []);

  // Drag start handler (placeholder - actual move in Plan 03)
  const handleDragStart = useCallback((_event: DragEvent, item: FolderChild) => {
    console.log('Drag started:', item.name);
  }, []);

  // Drop handler for folder tree (placeholder - actual move in Plan 03)
  const handleDrop = useCallback((targetFolderId: string, dataTransfer: DataTransfer) => {
    try {
      const data = dataTransfer.getData('application/json');
      if (data) {
        const item = JSON.parse(data);
        // TODO: Implement move in Plan 03
        console.log('Drop:', item.id, 'into folder:', targetFolderId);
      }
    } catch {
      // Ignore invalid drag data
    }
  }, []);

  // Upload click handler (placeholder - implemented in Plan 02)
  const handleUploadClick = useCallback(() => {
    // TODO: Implement upload dialog in Plan 02
    console.log('Upload clicked');
  }, []);

  // Get current folder's children
  const children = currentFolder?.children ?? [];
  const hasChildren = children.length > 0;

  return (
    <div className="file-browser">
      {/* Sidebar with folder tree */}
      <aside className="file-browser-sidebar">
        <FolderTree
          currentFolderId={currentFolderId}
          onNavigate={handleNavigate}
          onDrop={handleDrop}
        />
      </aside>

      {/* Main content area */}
      <main className="file-browser-main">
        {/* Loading state */}
        {isLoading && (
          <div className="file-browser-loading">
            <span className="file-browser-loading-spinner">Loading...</span>
          </div>
        )}

        {/* File list or empty state */}
        {!isLoading && hasChildren && (
          <FileList
            items={children}
            selectedId={selectedItemId}
            parentId={currentFolderId}
            onSelect={handleSelect}
            onNavigate={handleNavigate}
            onContextMenu={handleContextMenu}
            onDragStart={handleDragStart}
          />
        )}

        {!isLoading && !hasChildren && <EmptyState onUploadClick={handleUploadClick} />}
      </main>
    </div>
  );
}
