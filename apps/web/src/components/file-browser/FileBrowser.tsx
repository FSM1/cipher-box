import { useState, useCallback, type DragEvent, type MouseEvent } from 'react';
import type { FolderChild, FileEntry } from '@cipherbox/crypto';
import { useFolderNavigation } from '../../hooks/useFolderNavigation';
import { useFolder } from '../../hooks/useFolder';
import { useFileDownload } from '../../hooks/useFileDownload';
import { useContextMenu } from '../../hooks/useContextMenu';
import { FolderTree } from './FolderTree';
import { FileList } from './FileList';
import { EmptyState } from './EmptyState';
import { ContextMenu } from './ContextMenu';
import { ConfirmDialog } from './ConfirmDialog';
import { RenameDialog } from './RenameDialog';
import { UploadZone } from './UploadZone';
import { UploadModal } from './UploadModal';
import { Breadcrumbs } from './Breadcrumbs';

/**
 * Type guard for file entries.
 */
function isFileEntry(item: FolderChild): item is FileEntry {
  return item.type === 'file';
}

/**
 * Dialog state for rename/delete operations.
 */
type DialogState = {
  open: boolean;
  item: FolderChild | null;
};

/**
 * Main file browser container component.
 *
 * Orchestrates the sidebar folder tree and main file list area.
 * Manages selection state, context menu, and file/folder actions.
 *
 * Layout:
 * - Left sidebar: FolderTree for navigation
 * - Main area: FileList or EmptyState based on folder contents
 *
 * Actions:
 * - Download: Downloads file from IPFS, decrypts, and triggers browser download
 * - Rename: Opens dialog to rename file/folder
 * - Delete: Shows confirmation, then removes from folder metadata
 * - Move: Drag-drop to sidebar folder tree
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
  const { currentFolderId, currentFolder, breadcrumbs, isLoading, navigateTo, navigateUp } =
    useFolderNavigation();

  // Folder operations
  const { renameItem, moveItem, deleteItem, isLoading: isOperating } = useFolder();

  // File download
  const { download, isDownloading } = useFileDownload();

  // Context menu state
  const contextMenu = useContextMenu();

  // Selection state (single selection per CONTEXT.md)
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);

  // Dialog states
  const [confirmDialog, setConfirmDialog] = useState<DialogState>({ open: false, item: null });
  const [renameDialog, setRenameDialog] = useState<DialogState>({ open: false, item: null });

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

  // Context menu handler - show context menu
  const handleContextMenu = useCallback(
    (event: MouseEvent, item: FolderChild) => {
      contextMenu.show(event, item);
    },
    [contextMenu]
  );

  // Drag start handler
  const handleDragStart = useCallback((_event: DragEvent, _item: FolderChild) => {
    // Drag data is set by FileListItem component
  }, []);

  // Drop handler for folder tree - move item to target folder
  const handleDrop = useCallback(
    async (targetFolderId: string, dataTransfer: DataTransfer) => {
      try {
        const data = dataTransfer.getData('application/json');
        if (!data) return;

        const { id, type, parentId } = JSON.parse(data) as {
          id: string;
          type: 'file' | 'folder';
          parentId: string;
        };

        // Don't move to same folder
        if (parentId === targetFolderId) return;

        // Prevent moving folder into itself (checked in folder.service too)
        if (type === 'folder' && id === targetFolderId) return;

        await moveItem(id, type, parentId, targetFolderId);
      } catch (err) {
        console.error('Move failed:', err);
      }
    },
    [moveItem]
  );

  // Download action handler
  const handleDownload = useCallback(async () => {
    const item = contextMenu.item;
    if (!item || !isFileEntry(item)) return;

    try {
      // Map FileEntry fields to FileMetadata for download service
      await download({
        cid: item.cid,
        iv: item.fileIv,
        wrappedKey: item.fileKeyEncrypted,
        originalName: item.name,
      });
    } catch (err) {
      console.error('Download failed:', err);
    }
  }, [contextMenu.item, download]);

  // Open rename dialog
  const handleRenameClick = useCallback(() => {
    if (contextMenu.item) {
      setRenameDialog({ open: true, item: contextMenu.item });
    }
  }, [contextMenu.item]);

  // Open delete confirmation dialog
  const handleDeleteClick = useCallback(() => {
    if (contextMenu.item) {
      setConfirmDialog({ open: true, item: contextMenu.item });
    }
  }, [contextMenu.item]);

  // Confirm rename
  const handleRenameConfirm = useCallback(
    async (newName: string) => {
      const item = renameDialog.item;
      if (!item) return;

      try {
        await renameItem(item.id, item.type, newName, currentFolderId);
        setRenameDialog({ open: false, item: null });
      } catch (err) {
        console.error('Rename failed:', err);
      }
    },
    [renameDialog.item, renameItem, currentFolderId]
  );

  // Confirm delete
  const handleDeleteConfirm = useCallback(async () => {
    const item = confirmDialog.item;
    if (!item) return;

    try {
      await deleteItem(item.id, item.type, currentFolderId);
      setConfirmDialog({ open: false, item: null });
    } catch (err) {
      console.error('Delete failed:', err);
    }
  }, [confirmDialog.item, deleteItem, currentFolderId]);

  // Close dialogs
  const closeConfirmDialog = useCallback(() => {
    setConfirmDialog({ open: false, item: null });
  }, []);

  const closeRenameDialog = useCallback(() => {
    setRenameDialog({ open: false, item: null });
  }, []);

  // Get current folder's children
  const children = currentFolder?.children ?? [];
  const hasChildren = children.length > 0;

  // Build delete confirmation message
  const deleteMessage =
    confirmDialog.item?.type === 'folder'
      ? `Are you sure you want to delete "${confirmDialog.item?.name}"? This will also delete all files and subfolders inside. This cannot be undone.`
      : `Are you sure you want to delete "${confirmDialog.item?.name}"? This cannot be undone.`;

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
        {/* Breadcrumbs + upload zone in toolbar area */}
        <div className="file-browser-toolbar">
          <Breadcrumbs
            breadcrumbs={breadcrumbs}
            onNavigate={handleNavigate}
            onNavigateUp={navigateUp}
          />
          <UploadZone folderId={currentFolderId} />
        </div>

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

        {!isLoading && !hasChildren && <EmptyState folderId={currentFolderId} />}
      </main>

      {/* Context menu */}
      {contextMenu.visible && contextMenu.item && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          item={contextMenu.item}
          onClose={contextMenu.hide}
          onDownload={isFileEntry(contextMenu.item) ? handleDownload : undefined}
          onRename={handleRenameClick}
          onDelete={handleDeleteClick}
        />
      )}

      {/* Rename dialog */}
      <RenameDialog
        open={renameDialog.open}
        onClose={closeRenameDialog}
        onConfirm={handleRenameConfirm}
        currentName={renameDialog.item?.name ?? ''}
        itemType={renameDialog.item?.type ?? 'file'}
        isLoading={isOperating}
      />

      {/* Delete confirmation dialog */}
      <ConfirmDialog
        open={confirmDialog.open}
        onClose={closeConfirmDialog}
        onConfirm={handleDeleteConfirm}
        title={confirmDialog.item?.type === 'folder' ? 'Delete Folder?' : 'Delete File?'}
        message={deleteMessage}
        confirmLabel="Delete"
        isDestructive
        isLoading={isOperating || isDownloading}
      />

      {/* Upload modal (self-manages visibility) */}
      <UploadModal />
    </div>
  );
}
