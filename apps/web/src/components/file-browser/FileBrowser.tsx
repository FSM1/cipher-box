import { useCallback } from 'react';
// TODO(phase 63): FolderEntry, FilePointer, isFilePointer removed — use SealedChildRef
import { useFolderNavigation } from '../../hooks/useFolderNavigation';
import { useFolder } from '../../hooks/useFolder';
import { useFileDownload } from '../../hooks/useFileDownload';
import { useContextMenu } from '../../hooks/useContextMenu';
import { useSyncPolling, invalidateOpenFolder } from '../../hooks/useSyncPolling';
import { useDeviceRegistrySync } from '../../hooks/useDeviceRegistrySync';
import { useDropUpload } from '../../hooks/useDropUpload';
import { isPreviewableFile, isTextFile } from '../../utils/fileTypes';
import { useVaultStore } from '../../stores/vault.store';
import { useSyncStore } from '../../stores/sync.store';
import { useUploadStore } from '../../stores/upload.store';
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

  // Plan 09 (68.2-09): `currentFolder.children` is now the SDK's resolved
  // `ResolvedChild[]` display projection (kind/size/modifiedAt pre-resolved,
  // SC#2). `useFileBrowserActions`/`FileList` still need the same-session
  // raw `SealedChildRef[]` identity/crypto carrier (`rawChildren`, D-09) for
  // selection/context-menu/download/drag callbacks and dialogs.
  const rawChildren = currentFolder?.rawChildren ?? [];

  const actions = useFileBrowserActions({
    currentFolderId,
    currentFolder: currentFolder
      ? { children: rawChildren, folderKey: currentFolder.folderKey }
      : null,
    resolvedChildren: currentFolder?.children ?? [],
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

  const hasChildren = rawChildren.length > 0;

  // Show FileList (with progress rows) instead of EmptyState when uploads are
  // actively targeting this folder, even if the folder has no committed children yet.
  const hasUploadsForFolder = useUploadStore((s) => {
    for (const f of s.files.values()) {
      if (f.targetFolderId === currentFolderId) return true;
    }
    return false;
  });

  // TODO(phase 63): SealedChildRef has no .type; treat all as folders for delete message
  const deleteMessage = `Are you sure you want to delete "${actions.confirmDialog.item?.name}"? This will also delete all files and subfolders inside. This cannot be undone.`;

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
            <UploadZone
              folderId={currentFolderId}
              onUploadComplete={() => {
                // 68.2-16: refresh the CURRENTLY OPEN folder immediately -- the
                // upload targets `currentFolderId`, which may be a subfolder,
                // but `handleSync` only ever resyncs root. Without this the
                // just-uploaded child never appears in a subfolder view until
                // the 30s poll's `invalidateOpenFolder` leg happens to fire.
                // Then run the root/tree + search-index resync (best-effort).
                void invalidateOpenFolder()
                  .catch(() => {})
                  .finally(() => {
                    void actions.handleSync().catch(() => {});
                  });
              }}
            />
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

      {!isLoading && (hasChildren || hasUploadsForFolder) && (
        <FileList
          items={rawChildren}
          resolvedChildren={currentFolder?.children ?? []}
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

      {!isLoading &&
        (initialSyncComplete || currentFolderId !== 'root') &&
        !hasChildren &&
        !hasUploadsForFolder && <EmptyState folderId={currentFolderId} />}

      {actions.multiSelectActive && actions.selectedIds.size > 1 && (
        <SelectionActionBar
          selectedItems={actions.selectedItems}
          resolvedChildren={currentFolder?.children ?? []}
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
          resolvedChildren={currentFolder?.children ?? []}
          selectedCount={actions.selectedIds.size}
          onClose={contextMenu.hide}
          onDownload={actions.handleDownload}
          onEdit={
            /* phase-63 stub: text file edit deferred */
            isTextFile(contextMenu.item.name) ? actions.handleEditClick : undefined
          }
          onPreview={
            /* phase-63 stub: preview by name extension, no .type check */
            isPreviewableFile(contextMenu.item.name) ? actions.handlePreviewClick : undefined
          }
          onRename={actions.handleRenameClick}
          onMove={actions.handleMoveClick}
          onShare={actions.handleShareClick}
          onDelete={actions.handleDeleteClick}
          onDetails={actions.handleDetailsClick}
          onBatchDownload={actions.handleBatchDownload}
          onBatchMove={actions.selectedIds.size > 1 ? actions.handleBatchMoveClick : undefined}
          onBatchDelete={actions.selectedIds.size > 1 ? actions.handleBatchDeleteClick : undefined}
        />
      )}

      <RenameDialog
        open={actions.renameDialog.open}
        onClose={actions.closeRenameDialog}
        onConfirm={actions.handleRenameConfirm}
        currentName={actions.renameDialog.item?.name ?? ''}
        itemType={'folder' /* TODO(phase 63): SealedChildRef has no .type */}
        isLoading={isOperating}
      />

      <ConfirmDialog
        open={actions.confirmDialog.open}
        onClose={actions.closeConfirmDialog}
        onConfirm={actions.handleDeleteConfirm}
        title={'Delete Folder?' /* TODO(phase 63): SealedChildRef has no .type */}
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
        resolvedChildren={currentFolder?.children ?? []}
        folderKey={currentFolder?.folderKey ?? null}
        parentFolderId={currentFolderId}
      />

      {actions.shareItem && currentFolder && (
        <ShareDialog
          isOpen={!!actions.shareItem}
          onClose={actions.closeShareDialog}
          item={actions.shareItem}
          folderKey={currentFolder.folderKey}
          ipnsName={actions.shareItem.ipnsName /* TODO(phase 63): SealedChildRef.ipnsName */}
          parentFolderId={currentFolderId}
        />
      )}

      {/* TODO(phase 63): isFilePointer removed; pass item directly (SealedChildRef) */}
      <TextEditorDialog
        open={actions.editorDialog.open}
        onClose={actions.closeEditorDialog}
        item={actions.editorDialog.item ?? null}
        parentFolderId={currentFolderId}
        folderKey={currentFolder?.folderKey ?? null}
      />

      <ImagePreviewDialog
        open={actions.imagePreviewDialog.open}
        onClose={actions.closeImagePreviewDialog}
        item={actions.imagePreviewDialog.item ?? null}
        folderKey={currentFolder?.folderKey ?? null}
      />

      <PdfPreviewDialog
        open={actions.pdfPreviewDialog.open}
        onClose={actions.closePdfPreviewDialog}
        item={actions.pdfPreviewDialog.item ?? null}
        folderKey={currentFolder?.folderKey ?? null}
      />

      <AudioPlayerDialog
        open={actions.audioPlayerDialog.open}
        onClose={actions.closeAudioPlayerDialog}
        item={actions.audioPlayerDialog.item ?? null}
        folderKey={currentFolder?.folderKey ?? null}
      />

      <VideoPlayerDialog
        open={actions.videoPlayerDialog.open}
        onClose={actions.closeVideoPlayerDialog}
        item={actions.videoPlayerDialog.item ?? null}
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
