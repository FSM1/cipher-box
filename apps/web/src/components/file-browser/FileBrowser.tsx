import { useCallback } from 'react';
import type { FolderEntry, FilePointer } from '@cipherbox/core';
import { useFolderNavigation } from '../../hooks/useFolderNavigation';
import { useFolder } from '../../hooks/useFolder';
import { useFileDownload } from '../../hooks/useFileDownload';
import { useContextMenu } from '../../hooks/useContextMenu';
import { useSyncPolling } from '../../hooks/useSyncPolling';
import { useDeviceRegistrySync } from '../../hooks/useDeviceRegistrySync';
import { useDropUpload } from '../../hooks/useDropUpload';
import { isFilePointer, isPreviewableFile, isTextFile } from '../../utils/fileTypes';
import { useVaultStore } from '../../stores/vault.store';
import { useSyncStore } from '../../stores/sync.store';
import { FileList } from './FileList';
import { EmptyState } from './EmptyState';
import { ContextMenu } from './ContextMenu';
import { ConfirmDialog } from './ConfirmDialog';
import { RenameDialog } from './RenameDialog';
import { CreateFolderDialog } from './CreateFolderDialog';
import { MoveDialog } from './MoveDialog';
import { DetailsDialog } from './DetailsDialog';
import { ShareDialog } from './ShareDialog';
import { UploadZone } from './UploadZone';
import { TextEditorDialog } from './TextEditorDialog';
import { ImagePreviewDialog } from './ImagePreviewDialog';
import { PdfPreviewDialog } from './PdfPreviewDialog';
import { AudioPlayerDialog } from './AudioPlayerDialog';
import { VideoPlayerDialog } from './VideoPlayerDialog';
import { Breadcrumbs } from './Breadcrumbs';
import { SyncIndicator } from './SyncIndicator';
import { OfflineBanner } from './OfflineBanner';
import { SelectionActionBar } from './SelectionActionBar';
import { useFileBrowserActions } from './useFileBrowserActions';

/**
 * Main file browser container component.
 *
 * Thin presentational shell that delegates all handler logic to
 * useFileBrowserActions and renders the file list with dialogs.
 */
export function FileBrowser() {
  const { currentFolderId, currentFolder, breadcrumbs, isLoading, navigateTo, navigateUp } =
    useFolderNavigation();

  const {
    createFolder,
    renameItem,
    moveItem,
    moveItems,
    deleteItem,
    deleteItems,
    isLoading: isOperating,
  } = useFolder();

  const { downloadFromIpns, isDownloading } = useFileDownload();
  const { handleFileDrop } = useDropUpload();

  /** Re-trigger upload for a single failed file (retry button in UploadListItem). */
  const handleRetryUpload = useCallback(
    (file: File) => {
      handleFileDrop([file], currentFolderId);
    },
    [handleFileDrop, currentFolderId]
  );

  const contextMenu = useContextMenu();
  const { rootIpnsName } = useVaultStore();
  const initialSyncComplete = useSyncStore((state) => state.initialSyncComplete);
  const syncStatus = useSyncStore((state) => state.status);

  const actions = useFileBrowserActions({
    currentFolderId,
    currentFolder,
    breadcrumbs,
    navigateTo,
    navigateUp,
    createFolder,
    renameItem,
    moveItem,
    moveItems,
    deleteItem,
    deleteItems,
    isOperating,
    isDownloading,
    downloadFromIpns,
    handleFileDrop,
    contextMenu,
    rootIpnsName,
  });

  useSyncPolling(actions.handleSync);
  useDeviceRegistrySync();

  const children = currentFolder?.children ?? [];
  const hasChildren = children.length > 0;

  const deleteMessage =
    actions.confirmDialog.item?.type === 'folder'
      ? `Are you sure you want to delete "${actions.confirmDialog.item?.name}"? This will also delete all files and subfolders inside. This cannot be undone.`
      : `Are you sure you want to delete "${actions.confirmDialog.item?.name}"? This cannot be undone.`;

  const contentClassName = [
    'file-browser-content',
    actions.isDraggingExternal ? 'file-browser-content--drag-active' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div
      className={contentClassName}
      onDragEnter={actions.handleContentDragEnter}
      onDragOver={actions.handleContentDragOver}
      onDragLeave={actions.handleContentDragLeave}
      onDrop={actions.handleContentDrop}
    >
      {/* Toolbar with breadcrumbs and actions */}
      <div className="file-browser-toolbar">
        <Breadcrumbs
          breadcrumbs={breadcrumbs}
          onNavigate={actions.handleNavigate}
          onNavigateUp={navigateUp}
          onDrop={actions.handleDropOnFolder}
          onExternalFileDrop={actions.handleExternalFileDrop}
        />
        <div className="file-browser-actions">
          <button
            type="button"
            className="toolbar-btn toolbar-btn--primary file-browser-new-folder-button"
            onClick={actions.openCreateFolderDialog}
            disabled={isOperating}
            aria-label="New Folder"
          >
            +folder
          </button>
          <div className="toolbar-upload">
            <UploadZone folderId={currentFolderId} onUploadComplete={actions.handleSync} />
          </div>
          <SyncIndicator />
        </div>
      </div>

      <OfflineBanner />

      {isLoading && (
        <div className="file-browser-loading">
          <span className="file-browser-loading-spinner">Loading...</span>
        </div>
      )}

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

      {!isLoading && hasChildren && (
        <FileList
          items={children}
          selectedIds={actions.selectedIds}
          parentId={currentFolderId}
          folderKey={currentFolder?.folderKey ?? null}
          showParentRow={currentFolderId !== 'root'}
          onNavigateUp={navigateUp}
          onSelect={actions.handleSelect}
          onSelectAll={actions.handleSelectAll}
          onNavigate={actions.handleNavigate}
          onContextMenu={actions.handleContextMenu}
          onDragStart={actions.handleDragStart}
          onDropOnFolder={actions.handleDropOnFolder}
          onExternalFileDrop={actions.handleExternalFileDrop}
          onRetryUpload={handleRetryUpload}
        />
      )}

      {!isLoading && (initialSyncComplete || currentFolderId !== 'root') && !hasChildren && (
        <EmptyState folderId={currentFolderId} />
      )}

      {actions.multiSelectActive && actions.selectedIds.size > 1 && (
        <SelectionActionBar
          selectedItems={actions.selectedItems}
          isLoading={isOperating || isDownloading}
          onClearSelection={actions.clearSelection}
          onDownload={actions.handleBatchDownload}
          onMove={actions.handleBatchMoveClick}
          onDelete={actions.handleBatchDeleteClick}
        />
      )}

      {contextMenu.visible && contextMenu.item && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          item={contextMenu.item}
          selectedCount={actions.selectedIds.size}
          onClose={contextMenu.hide}
          onDownload={isFilePointer(contextMenu.item) ? actions.handleDownload : undefined}
          onEdit={
            isFilePointer(contextMenu.item) && isTextFile(contextMenu.item.name)
              ? actions.handleEditClick
              : undefined
          }
          onPreview={
            isFilePointer(contextMenu.item) && isPreviewableFile(contextMenu.item.name)
              ? actions.handlePreviewClick
              : undefined
          }
          onRename={actions.handleRenameClick}
          onMove={actions.handleMoveClick}
          onShare={actions.handleShareClick}
          onDelete={actions.handleDeleteClick}
          onDetails={actions.handleDetailsClick}
          onBatchDownload={
            actions.selectedIds.size > 1 && actions.selectedItems.some(isFilePointer)
              ? actions.handleBatchDownload
              : undefined
          }
          onBatchMove={actions.selectedIds.size > 1 ? actions.handleBatchMoveClick : undefined}
          onBatchDelete={actions.selectedIds.size > 1 ? actions.handleBatchDeleteClick : undefined}
        />
      )}

      <RenameDialog
        open={actions.renameDialog.open}
        onClose={actions.closeRenameDialog}
        onConfirm={actions.handleRenameConfirm}
        currentName={actions.renameDialog.item?.name ?? ''}
        itemType={actions.renameDialog.item?.type ?? 'file'}
        isLoading={isOperating}
      />

      <ConfirmDialog
        open={actions.confirmDialog.open}
        onClose={actions.closeConfirmDialog}
        onConfirm={actions.handleDeleteConfirm}
        title={actions.confirmDialog.item?.type === 'folder' ? 'Delete Folder?' : 'Delete File?'}
        message={deleteMessage}
        confirmLabel="Delete"
        isDestructive
        isLoading={isOperating || isDownloading}
      />

      <CreateFolderDialog
        open={actions.createFolderDialogOpen}
        onClose={actions.closeCreateFolderDialog}
        onConfirm={actions.handleCreateFolderConfirm}
        isLoading={isOperating}
      />

      <MoveDialog
        open={actions.moveDialog.open}
        onClose={actions.closeMoveDialog}
        onConfirm={actions.handleMoveConfirm}
        item={actions.moveDialog.item}
        currentFolderId={currentFolderId}
        isLoading={isOperating}
      />

      <DetailsDialog
        open={actions.detailsDialog.open}
        onClose={actions.closeDetailsDialog}
        item={actions.detailsDialog.item}
        folderKey={currentFolder?.folderKey ?? null}
        parentFolderId={currentFolderId}
      />

      {actions.shareItem && currentFolder && (
        <ShareDialog
          isOpen={!!actions.shareItem}
          onClose={actions.closeShareDialog}
          item={actions.shareItem}
          folderKey={currentFolder.folderKey}
          ipnsName={
            actions.shareItem.type === 'folder'
              ? (actions.shareItem as FolderEntry).ipnsName
              : (actions.shareItem as FilePointer).fileMetaIpnsName
          }
          parentFolderId={currentFolderId}
        />
      )}

      <TextEditorDialog
        open={actions.editorDialog.open}
        onClose={actions.closeEditorDialog}
        item={
          actions.editorDialog.item && isFilePointer(actions.editorDialog.item)
            ? actions.editorDialog.item
            : null
        }
        parentFolderId={currentFolderId}
        folderKey={currentFolder?.folderKey ?? null}
      />

      <ImagePreviewDialog
        open={actions.imagePreviewDialog.open}
        onClose={actions.closeImagePreviewDialog}
        item={
          actions.imagePreviewDialog.item && isFilePointer(actions.imagePreviewDialog.item)
            ? actions.imagePreviewDialog.item
            : null
        }
        folderKey={currentFolder?.folderKey ?? null}
      />

      <PdfPreviewDialog
        open={actions.pdfPreviewDialog.open}
        onClose={actions.closePdfPreviewDialog}
        item={
          actions.pdfPreviewDialog.item && isFilePointer(actions.pdfPreviewDialog.item)
            ? actions.pdfPreviewDialog.item
            : null
        }
        folderKey={currentFolder?.folderKey ?? null}
      />

      <AudioPlayerDialog
        open={actions.audioPlayerDialog.open}
        onClose={actions.closeAudioPlayerDialog}
        item={
          actions.audioPlayerDialog.item && isFilePointer(actions.audioPlayerDialog.item)
            ? actions.audioPlayerDialog.item
            : null
        }
        folderKey={currentFolder?.folderKey ?? null}
      />

      <VideoPlayerDialog
        open={actions.videoPlayerDialog.open}
        onClose={actions.closeVideoPlayerDialog}
        item={
          actions.videoPlayerDialog.item && isFilePointer(actions.videoPlayerDialog.item)
            ? actions.videoPlayerDialog.item
            : null
        }
        folderKey={currentFolder?.folderKey ?? null}
      />

      <ConfirmDialog
        open={actions.batchDeleteDialog.open}
        onClose={actions.closeBatchDeleteDialog}
        onConfirm={actions.handleBatchDeleteConfirm}
        title={`Delete ${actions.batchDeleteDialog.items.length} Items?`}
        message={`Are you sure you want to delete ${actions.batchDeleteDialog.items.length} selected items? Any folders will also have their contents deleted. This cannot be undone.`}
        confirmLabel="Delete All"
        isDestructive
        isLoading={isOperating}
      />

      <MoveDialog
        open={actions.batchMoveDialog.open}
        onClose={actions.closeBatchMoveDialog}
        onConfirm={actions.handleBatchMoveConfirm}
        item={null}
        items={actions.batchMoveDialog.items}
        currentFolderId={currentFolderId}
        isLoading={isOperating}
      />
    </div>
  );
}
