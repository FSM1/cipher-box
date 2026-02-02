import { useState, useCallback, type DragEvent, type MouseEvent } from 'react';
import type { FolderChild, FileEntry } from '@cipherbox/crypto';
import { useFolderNavigation } from '../../hooks/useFolderNavigation';
import { useFolder } from '../../hooks/useFolder';
import { useFileDownload } from '../../hooks/useFileDownload';
import { useContextMenu } from '../../hooks/useContextMenu';
import { FileList } from './FileList';
import { EmptyState } from './EmptyState';
import { ContextMenu } from './ContextMenu';
import { ConfirmDialog } from './ConfirmDialog';
import { RenameDialog } from './RenameDialog';
import { CreateFolderDialog } from './CreateFolderDialog';
import { MoveDialog } from './MoveDialog';
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
 * Manages the file list area with in-place navigation.
 * Selection state, context menu, and file/folder actions.
 *
 * Navigation:
 * - Double-click folders to navigate into them
 * - Click [..] PARENT_DIR row to navigate up
 * - Browser history integration via URL routing
 *
 * Actions:
 * - Download: Downloads file from IPFS, decrypts, and triggers browser download
 * - Rename: Opens dialog to rename file/folder
 * - Delete: Shows confirmation, then removes from folder metadata
 * - Move: Drag-drop to folder rows in list
 *
 * @example
 * ```tsx
 * function FilesPage() {
 *   return (
 *     <main className="app-main">
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
  const { createFolder, renameItem, moveItem, deleteItem, isLoading: isOperating } = useFolder();

  // File download
  const { download, isDownloading } = useFileDownload();

  // Context menu state
  const contextMenu = useContextMenu();

  // Selection state (single selection per CONTEXT.md)
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);

  // Dialog states
  const [confirmDialog, setConfirmDialog] = useState<DialogState>({ open: false, item: null });
  const [renameDialog, setRenameDialog] = useState<DialogState>({ open: false, item: null });
  const [moveDialog, setMoveDialog] = useState<DialogState>({ open: false, item: null });
  const [createFolderDialogOpen, setCreateFolderDialogOpen] = useState(false);

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

  // Drop on folder handler
  const handleDropOnFolder = useCallback(
    async (
      sourceId: string,
      sourceType: 'file' | 'folder',
      sourceParentId: string,
      destFolderId: string
    ) => {
      try {
        await moveItem(sourceId, sourceType, sourceParentId, destFolderId);
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

  // Open move dialog
  const handleMoveClick = useCallback(() => {
    if (contextMenu.item) {
      setMoveDialog({ open: true, item: contextMenu.item });
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

  // Confirm move
  const handleMoveConfirm = useCallback(
    async (destinationFolderId: string) => {
      const item = moveDialog.item;
      if (!item) return;

      try {
        await moveItem(item.id, item.type, currentFolderId, destinationFolderId);
        setMoveDialog({ open: false, item: null });
      } catch (err) {
        console.error('Move failed:', err);
      }
    },
    [moveDialog.item, moveItem, currentFolderId]
  );

  // Close dialogs
  const closeConfirmDialog = useCallback(() => {
    setConfirmDialog({ open: false, item: null });
  }, []);

  const closeRenameDialog = useCallback(() => {
    setRenameDialog({ open: false, item: null });
  }, []);

  const closeMoveDialog = useCallback(() => {
    setMoveDialog({ open: false, item: null });
  }, []);

  // Create folder handlers
  const openCreateFolderDialog = useCallback(() => {
    setCreateFolderDialogOpen(true);
  }, []);

  const closeCreateFolderDialog = useCallback(() => {
    setCreateFolderDialogOpen(false);
  }, []);

  const handleCreateFolderConfirm = useCallback(
    async (name: string) => {
      try {
        await createFolder(name, currentFolderId === 'root' ? null : currentFolderId);
        setCreateFolderDialogOpen(false);
      } catch (err) {
        console.error('Create folder failed:', err);
      }
    },
    [createFolder, currentFolderId]
  );

  // Get current folder's children
  const children = currentFolder?.children ?? [];
  const hasChildren = children.length > 0;

  // Build delete confirmation message
  const deleteMessage =
    confirmDialog.item?.type === 'folder'
      ? `Are you sure you want to delete "${confirmDialog.item?.name}"? This will also delete all files and subfolders inside. This cannot be undone.`
      : `Are you sure you want to delete "${confirmDialog.item?.name}"? This cannot be undone.`;

  return (
    <div className="file-browser-content">
      {/* Toolbar with breadcrumbs and actions */}
      <div className="file-browser-toolbar">
        <Breadcrumbs
          breadcrumbs={breadcrumbs}
          onNavigate={handleNavigate}
          onNavigateUp={navigateUp}
          onDrop={handleDropOnFolder}
        />
        <div className="file-browser-actions">
          <button
            type="button"
            className="toolbar-btn toolbar-btn--primary"
            onClick={openCreateFolderDialog}
            disabled={isOperating}
            aria-label="New Folder"
          >
            +folder
          </button>
          <div className="toolbar-upload">
            <UploadZone folderId={currentFolderId} />
          </div>
        </div>
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
          showParentRow={currentFolderId !== 'root'}
          onNavigateUp={navigateUp}
          onSelect={handleSelect}
          onNavigate={handleNavigate}
          onContextMenu={handleContextMenu}
          onDragStart={handleDragStart}
          onDropOnFolder={handleDropOnFolder}
        />
      )}

      {!isLoading && !hasChildren && <EmptyState folderId={currentFolderId} />}

      {/* Context menu */}
      {contextMenu.visible && contextMenu.item && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          item={contextMenu.item}
          onClose={contextMenu.hide}
          onDownload={isFileEntry(contextMenu.item) ? handleDownload : undefined}
          onRename={handleRenameClick}
          onMove={handleMoveClick}
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

      {/* Create folder dialog */}
      <CreateFolderDialog
        open={createFolderDialogOpen}
        onClose={closeCreateFolderDialog}
        onConfirm={handleCreateFolderConfirm}
        isLoading={isOperating}
      />

      {/* Move dialog */}
      <MoveDialog
        open={moveDialog.open}
        onClose={closeMoveDialog}
        onConfirm={handleMoveConfirm}
        item={moveDialog.item}
        currentFolderId={currentFolderId}
        isLoading={isOperating}
      />

      {/* Upload modal (self-manages visibility) */}
      <UploadModal />
    </div>
  );
}
