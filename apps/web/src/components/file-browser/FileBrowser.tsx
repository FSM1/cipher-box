import { useState, useCallback, useEffect, useRef, type DragEvent, type MouseEvent } from 'react';
import type { FolderChild, FileEntry } from '@cipherbox/crypto';
import { useFolderNavigation } from '../../hooks/useFolderNavigation';
import { useFolder } from '../../hooks/useFolder';
import { useFileDownload } from '../../hooks/useFileDownload';
import { useContextMenu } from '../../hooks/useContextMenu';
import { useSyncPolling } from '../../hooks/useSyncPolling';
import { useDropUpload, isExternalFileDrag } from '../../hooks/useDropUpload';
import { useVaultStore } from '../../stores/vault.store';
import { useFolderStore } from '../../stores/folder.store';
import { useSyncStore } from '../../stores/sync.store';
import { resolveIpnsRecord } from '../../services/ipns.service';
import { fetchAndDecryptMetadata } from '../../services/folder.service';
import { FileList } from './FileList';
import { EmptyState } from './EmptyState';
import { ContextMenu } from './ContextMenu';
import { ConfirmDialog } from './ConfirmDialog';
import { RenameDialog } from './RenameDialog';
import { CreateFolderDialog } from './CreateFolderDialog';
import { MoveDialog } from './MoveDialog';
import { DetailsDialog } from './DetailsDialog';
import { UploadZone } from './UploadZone';
import { TextEditorDialog } from './TextEditorDialog';
import { ImagePreviewDialog } from './ImagePreviewDialog';
import { UploadModal } from './UploadModal';
import { Breadcrumbs } from './Breadcrumbs';
import { SyncIndicator } from './SyncIndicator';
import { OfflineBanner } from './OfflineBanner';

/**
 * Type guard for file entries.
 */
function isFileEntry(item: FolderChild): item is FileEntry {
  return item.type === 'file';
}

/** Extensions recognized as editable text files. */
const TEXT_EXTENSIONS = new Set([
  '.txt',
  '.md',
  '.json',
  '.yaml',
  '.yml',
  '.xml',
  '.csv',
  '.log',
  '.env',
  '.toml',
  '.ini',
  '.cfg',
  '.conf',
  '.sh',
  '.bash',
  '.zsh',
  '.fish',
  '.html',
  '.css',
  '.js',
  '.ts',
  '.jsx',
  '.tsx',
  '.py',
  '.rb',
  '.rs',
  '.go',
  '.java',
  '.c',
  '.cpp',
  '.h',
  '.hpp',
  '.sql',
  '.graphql',
  '.gitignore',
  '.editorconfig',
]);

/** Well-known extensionless text filenames. */
const TEXT_FILENAMES = new Set([
  'dockerfile',
  'makefile',
  'rakefile',
  'gemfile',
  'procfile',
  'vagrantfile',
]);

/**
 * Check if a filename has a text-editable extension.
 */
function isTextFile(name: string): boolean {
  const lower = name.toLowerCase();
  // Handle dotfiles like .gitignore, .editorconfig
  if (TEXT_EXTENSIONS.has(lower)) return true;
  // Handle well-known extensionless filenames like Dockerfile, Makefile
  if (TEXT_FILENAMES.has(lower)) return true;
  const lastDot = lower.lastIndexOf('.');
  if (lastDot === -1) return false;
  return TEXT_EXTENSIONS.has(lower.slice(lastDot));
}

/** Extensions recognized as previewable image files. */
const IMAGE_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.svg',
  '.bmp',
  '.ico',
  '.avif',
]);

/**
 * Check if a filename has a previewable image extension.
 */
function isImageFile(name: string): boolean {
  const lower = name.toLowerCase();
  const lastDot = lower.lastIndexOf('.');
  if (lastDot === -1) return false;
  return IMAGE_EXTENSIONS.has(lower.slice(lastDot));
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

  // External file drop upload
  const { handleFileDrop } = useDropUpload();

  // Context menu state
  const contextMenu = useContextMenu();

  // Vault and folder stores for sync
  const { rootIpnsName } = useVaultStore();
  const initialSyncComplete = useSyncStore((state) => state.initialSyncComplete);
  const syncStatus = useSyncStore((state) => state.status);

  // Sync callback - compare remote sequence with local, refresh if different
  const handleSync = useCallback(async () => {
    if (!rootIpnsName) return;

    // Resolve root folder IPNS to get remote CID and sequence number
    const resolved = await resolveIpnsRecord(rootIpnsName);
    if (!resolved) {
      // If initial sync hasn't completed yet, signal that IPNS isn't available
      // so useSyncPolling keeps the syncing state visible and retries
      if (!useSyncStore.getState().initialSyncComplete) {
        throw new Error('IPNS not resolved yet');
      }
      return;
    }

    // Read fresh state from store — avoid stale closure from render cycle.
    // On initial load, the root folder may not be in the closure's `folders`
    // yet because useFolderNavigation's useEffect sets it in the same commit.
    const rootFolder = useFolderStore.getState().folders['root'];
    if (!rootFolder) return;

    // Compare sequence numbers - if remote > local, we need to refresh
    // Sequence number comparison is more reliable than CID since we
    // don't cache the local CID, and sequence always increments
    if (resolved.sequenceNumber <= rootFolder.sequenceNumber) {
      // No changes, already up to date
      return;
    }

    // Remote has newer version - fetch and decrypt new metadata
    try {
      const metadata = await fetchAndDecryptMetadata(resolved.cid, rootFolder.folderKey);

      // Update folder store with new children
      // Per CONTEXT.md: last write wins, instant refresh (no toast/prompt)
      useFolderStore.getState().updateFolderChildren('root', metadata.children);
      useFolderStore.getState().updateFolderSequence('root', resolved.sequenceNumber);
    } catch (err) {
      console.error('Sync refresh failed:', err);
      // During initial sync, propagate so useSyncPolling keeps the
      // loading UI visible and retries instead of showing empty state
      if (!useSyncStore.getState().initialSyncComplete) {
        throw err;
      }
    }
  }, [rootIpnsName]);

  // Start sync polling (30s interval, pauses when backgrounded/offline)
  useSyncPolling(handleSync);

  // External drag state — tracks when files from OS are being dragged over
  const [isDraggingExternal, setIsDraggingExternal] = useState(false);
  const dragCounterRef = useRef(0);

  /**
   * Detect external file drag entering the content area.
   * Uses a counter to handle nested dragenter/dragleave events correctly.
   */
  const handleContentDragEnter = useCallback((e: DragEvent) => {
    if (isExternalFileDrag(e.dataTransfer)) {
      dragCounterRef.current += 1;
      if (dragCounterRef.current === 1) {
        setIsDraggingExternal(true);
      }
    }
  }, []);

  const handleContentDragOver = useCallback((e: DragEvent) => {
    if (isExternalFileDrag(e.dataTransfer)) {
      e.preventDefault();
      e.dataTransfer.dropEffect = 'copy';
    }
  }, []);

  const handleContentDragLeave = useCallback((e: DragEvent) => {
    if (isExternalFileDrag(e.dataTransfer)) {
      dragCounterRef.current -= 1;
      if (dragCounterRef.current <= 0) {
        dragCounterRef.current = 0;
        setIsDraggingExternal(false);
      }
    }
  }, []);

  // Reset drag state if user abandons drag outside the window (e.g. drops on desktop
  // or presses Escape). Without this the counter/overlay can get stuck.
  useEffect(() => {
    const resetDragState = () => {
      dragCounterRef.current = 0;
      setIsDraggingExternal(false);
    };
    const handleWindowDrop = (e: Event) => {
      e.preventDefault();
      resetDragState();
    };
    const handleWindowDragLeave = (e: globalThis.DragEvent) => {
      // relatedTarget is null when the drag leaves the browser window entirely
      if (!e.relatedTarget) {
        resetDragState();
      }
    };
    window.addEventListener('dragend', resetDragState);
    window.addEventListener('drop', handleWindowDrop);
    window.addEventListener('dragleave', handleWindowDragLeave as EventListener);
    return () => {
      window.removeEventListener('dragend', resetDragState);
      window.removeEventListener('drop', handleWindowDrop);
      window.removeEventListener('dragleave', handleWindowDragLeave as EventListener);
    };
  }, []);

  /**
   * Catch-all drop handler for the content area.
   * If files from OS are dropped on general area (not intercepted by a child),
   * upload them to the current folder.
   */
  const handleContentDrop = useCallback(
    (e: DragEvent) => {
      dragCounterRef.current = 0;
      setIsDraggingExternal(false);

      // Only handle external file drops
      if (!e.dataTransfer.files || e.dataTransfer.files.length === 0) return;
      if (!isExternalFileDrag(e.dataTransfer)) return;

      e.preventDefault();
      const files = Array.from(e.dataTransfer.files);
      handleFileDrop(files, currentFolderId);
    },
    [handleFileDrop, currentFolderId]
  );

  /**
   * Handle external file drops targeting a specific folder.
   * Called by FileListItem (folder rows) and Breadcrumbs.
   */
  const handleExternalFileDrop = useCallback(
    (files: File[], targetFolderId: string) => {
      dragCounterRef.current = 0;
      setIsDraggingExternal(false);
      handleFileDrop(files, targetFolderId);
    },
    [handleFileDrop]
  );

  // Selection state (single selection per CONTEXT.md)
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);

  // Dialog states
  const [confirmDialog, setConfirmDialog] = useState<DialogState>({ open: false, item: null });
  const [renameDialog, setRenameDialog] = useState<DialogState>({ open: false, item: null });
  const [moveDialog, setMoveDialog] = useState<DialogState>({ open: false, item: null });
  const [detailsDialog, setDetailsDialog] = useState<DialogState>({ open: false, item: null });
  const [editorDialog, setEditorDialog] = useState<DialogState>({ open: false, item: null });
  const [imagePreviewDialog, setImagePreviewDialog] = useState<DialogState>({
    open: false,
    item: null,
  });
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

  // Open details dialog
  const handleDetailsClick = useCallback(() => {
    if (contextMenu.item) {
      setDetailsDialog({ open: true, item: contextMenu.item });
    }
  }, [contextMenu.item]);

  // Open text editor dialog
  const handleEditClick = useCallback(() => {
    if (contextMenu.item) {
      setEditorDialog({ open: true, item: contextMenu.item });
    }
  }, [contextMenu.item]);

  // Open image preview dialog
  const handlePreviewClick = useCallback(() => {
    if (contextMenu.item) {
      setImagePreviewDialog({ open: true, item: contextMenu.item });
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

  const closeDetailsDialog = useCallback(() => {
    setDetailsDialog({ open: false, item: null });
  }, []);

  const closeEditorDialog = useCallback(() => {
    setEditorDialog({ open: false, item: null });
  }, []);

  const closeImagePreviewDialog = useCallback(() => {
    setImagePreviewDialog({ open: false, item: null });
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

  const contentClassName = [
    'file-browser-content',
    isDraggingExternal ? 'file-browser-content--drag-active' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div
      className={contentClassName}
      onDragEnter={handleContentDragEnter}
      onDragOver={handleContentDragOver}
      onDragLeave={handleContentDragLeave}
      onDrop={handleContentDrop}
    >
      {/* Toolbar with breadcrumbs and actions */}
      <div className="file-browser-toolbar">
        <Breadcrumbs
          breadcrumbs={breadcrumbs}
          onNavigate={handleNavigate}
          onNavigateUp={navigateUp}
          onDrop={handleDropOnFolder}
          onExternalFileDrop={handleExternalFileDrop}
        />
        <div className="file-browser-actions">
          <button
            type="button"
            className="toolbar-btn toolbar-btn--primary file-browser-new-folder-button"
            onClick={openCreateFolderDialog}
            disabled={isOperating}
            aria-label="New Folder"
          >
            +folder
          </button>
          <div className="toolbar-upload">
            <UploadZone folderId={currentFolderId} />
          </div>
          <SyncIndicator />
        </div>
      </div>

      {/* Offline banner */}
      <OfflineBanner />

      {/* Loading state */}
      {isLoading && (
        <div className="file-browser-loading">
          <span className="file-browser-loading-spinner">Loading...</span>
        </div>
      )}

      {/* Initial vault sync state — shown before first IPNS resolve completes (root only) */}
      {!isLoading && !initialSyncComplete && currentFolderId === 'root' && !hasChildren && (
        <div className="vault-syncing" data-testid="vault-syncing" role="status" aria-live="polite">
          <pre className="vault-syncing-ascii" aria-hidden="true">
            {`> vault sync in progress...
> resolving ipns records`}
          </pre>
          <div className="vault-syncing-bar">
            <div className="vault-syncing-bar-fill" />
          </div>
          <p className="vault-syncing-text">
            {syncStatus === 'error' ? '// SYNC FAILED — retrying...' : '// SYNCING VAULT...'}
          </p>
          <p className="vault-syncing-hint">fetching encrypted metadata from the network</p>
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
          onExternalFileDrop={handleExternalFileDrop}
        />
      )}

      {!isLoading && (initialSyncComplete || currentFolderId !== 'root') && !hasChildren && (
        <EmptyState folderId={currentFolderId} />
      )}

      {/* Context menu */}
      {contextMenu.visible && contextMenu.item && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          item={contextMenu.item}
          onClose={contextMenu.hide}
          onDownload={isFileEntry(contextMenu.item) ? handleDownload : undefined}
          onEdit={
            isFileEntry(contextMenu.item) && isTextFile(contextMenu.item.name)
              ? handleEditClick
              : undefined
          }
          onPreview={
            isFileEntry(contextMenu.item) && isImageFile(contextMenu.item.name)
              ? handlePreviewClick
              : undefined
          }
          onRename={handleRenameClick}
          onMove={handleMoveClick}
          onDelete={handleDeleteClick}
          onDetails={handleDetailsClick}
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

      {/* Details dialog */}
      <DetailsDialog
        open={detailsDialog.open}
        onClose={closeDetailsDialog}
        item={detailsDialog.item}
        parentFolderId={currentFolderId}
      />

      {/* Text editor dialog */}
      <TextEditorDialog
        open={editorDialog.open}
        onClose={closeEditorDialog}
        item={editorDialog.item && isFileEntry(editorDialog.item) ? editorDialog.item : null}
        parentFolderId={currentFolderId}
      />

      {/* Image preview dialog */}
      <ImagePreviewDialog
        open={imagePreviewDialog.open}
        onClose={closeImagePreviewDialog}
        item={
          imagePreviewDialog.item && isFileEntry(imagePreviewDialog.item)
            ? imagePreviewDialog.item
            : null
        }
      />

      {/* Upload modal (self-manages visibility) */}
      <UploadModal />
    </div>
  );
}
