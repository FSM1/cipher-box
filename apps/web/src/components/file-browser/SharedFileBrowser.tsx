/**
 * SharedFileBrowser -- File browser for shared content with conditional write support.
 *
 * Shows items shared with the current user at ~/shared.
 * - Top-level: flat list of received shares with SHARED BY column
 * - Inside folder: standard file list with [RW]/[RO] badges
 * - Write shares: upload/mkdir toolbar, full context menu (rename, delete)
 * - Read-only shares: no write actions, download/preview/details only
 * - Drag-and-drop upload zone for write shares
 */

import type React from 'react';
import {
  useState,
  useCallback,
  useRef,
  useEffect,
  useMemo,
  type MouseEvent,
  type DragEvent,
} from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import type { ResolvedChild } from '@cipherbox/sdk';
import { useSharedNavigation } from '../../hooks/useSharedNavigation';
import { useContextMenu } from '../../hooks/useContextMenu';
import {
  isTextFile,
  isImageFile,
  isPdfFile,
  isAudioFile,
  isVideoFile,
  isPreviewableFile,
  isFileRefResolved,
} from '../../utils/fileTypes';
import { ContextMenu } from './ContextMenu';
import { DetailsDialog } from './DetailsDialog';
import { ImagePreviewDialog } from './ImagePreviewDialog';
import { PdfPreviewDialog } from './PdfPreviewDialog';
import { AudioPlayerDialog } from './AudioPlayerDialog';
import { VideoPlayerDialog } from './VideoPlayerDialog';
import { TextEditorDialog } from './TextEditorDialog';
import { SharedListRow } from './SharedListRow';
import { SharedFolderRow } from './SharedFolderRow';
import { SharedMoveDialog } from './SharedMoveDialog';
import { SelectionActionBar } from './SelectionActionBar';
import '../../styles/shared-browser.css';

/**
 * Sort items folders-first (by resolved kind), then alphabetically by name.
 * SharedFileBrowser has no upload-in-progress virtual rows, so no
 * `'_uploading' in item` short-circuit is needed here (unlike FileList.tsx).
 */
function sortItems(
  items: SealedChildRef[],
  resolvedByIpnsName: Map<string, ResolvedChild>
): SealedChildRef[] {
  return [...items].sort((a, b) => {
    const aIsFolder = !isFileRefResolved(a, resolvedByIpnsName);
    const bIsFolder = !isFileRefResolved(b, resolvedByIpnsName);
    if (aIsFolder !== bIsFolder) return aIsFolder ? -1 : 1;
    return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
  });
}

type DialogState = {
  open: boolean;
  item: SealedChildRef | null;
};

/**
 * Terminal-style ASCII art for shared empty state.
 */
const sharedEmptyArt = `\u250C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
\u2502 $ ls ~/shared        \u2502
\u2502 total 0              \u2502
\u2502 $ \u2588                  \u2502
\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518`;

export function SharedFileBrowser() {
  const {
    currentView,
    sharedItems,
    folderChildren,
    resolvedChildren,
    currentShareId,
    folderKey,
    breadcrumbs,
    isLoading,
    error,
    permission,
    navigateToShare,
    navigateToSubfolder,
    navigateUp,
    navigateToRoot,
    navigateToBreadcrumb,
    downloadSharedFile,
    loadSharedFileContent,
    saveSharedSingleFile,
    hideSharedItem,
    uploadFile,
    createFolder,
    renameItem,
    deleteItem,
    updateSharedFile,
    moveItem,
    batchMoveItems,
  } = useSharedNavigation();

  const contextMenu = useContextMenu();

  // Dialog states
  const [detailsDialog, setDetailsDialog] = useState<DialogState>({ open: false, item: null });
  const [editorDialog, setEditorDialog] = useState<DialogState>({ open: false, item: null });
  const [imagePreviewDialog, setImagePreviewDialog] = useState<DialogState>({
    open: false,
    item: null,
  });
  const [pdfPreviewDialog, setPdfPreviewDialog] = useState<DialogState>({
    open: false,
    item: null,
  });
  const [audioPlayerDialog, setAudioPlayerDialog] = useState<DialogState>({
    open: false,
    item: null,
  });
  const [videoPlayerDialog, setVideoPlayerDialog] = useState<DialogState>({
    open: false,
    item: null,
  });

  // Track which shared item the context menu is for (for hide action)
  const [contextShareId, setContextShareId] = useState<string | null>(null);

  // Inline new folder creation state
  const [showNewFolderInput, setShowNewFolderInput] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const newFolderInputRef = useRef<HTMLInputElement>(null);

  // File input ref for upload button
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Drag-and-drop state
  const [isDragOver, setIsDragOver] = useState(false);

  // Move dialog state
  const [moveDialogItem, setMoveDialogItem] = useState<SealedChildRef | null>(null);
  const handleMoveClick = useCallback((item: SealedChildRef) => setMoveDialogItem(item), []);

  // ---------------------------------------------------------------------------
  // Multi-select selection state (mirrors useFileBrowserActions :218-235)
  // ---------------------------------------------------------------------------

  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const selectedItems = useMemo(
    () => folderChildren.filter((c) => selectedIds.has(c.ipnsName)),
    [folderChildren, selectedIds]
  );

  // 68.2-08 (D-02): resolved display projection, keyed by ipnsName -- passed
  // to SharedFolderRow's `resolved` prop so kind/size/modifiedAt render from
  // the SDK-resolved listing (client.listSharedFolder) instead of the legacy
  // SealedChildRef display-mirror fields. `folderChildren` itself stays the
  // identity/crypto carrier for every write-op/dialog call site below.
  const resolvedByIpnsName = useMemo(
    () => new Map(resolvedChildren.map((r) => [r.ipnsName, r])),
    [resolvedChildren]
  );
  // The batch action bar only appears for a genuine multi-selection (>1), mirroring
  // the private vault (FileBrowser :205 `selectedIds.size > 1`). Gating on >0 would
  // make a plain single click — which is also the first click of a double-click —
  // pop the bar in above the list, shifting the rows down so the second click of
  // the double-click misses the row and folder navigation never fires.
  const multiSelectActive = selectedIds.size > 1;

  const clearSelection = useCallback(() => {
    setSelectedIds(new Set());
  }, []);

  const handleSelect = useCallback(
    (itemId: string, event: { ctrlKey: boolean; shiftKey: boolean; metaKey: boolean }) => {
      const isCtrl = event.ctrlKey || event.metaKey;
      if (isCtrl) {
        setSelectedIds((prev) => {
          const next = new Set(prev);
          if (next.has(itemId)) next.delete(itemId);
          else next.add(itemId);
          return next;
        });
      } else {
        setSelectedIds(new Set([itemId]));
      }
    },
    []
  );

  // Prune selected IDs when folder children change (navigation)
  useEffect(() => {
    setSelectedIds((prev) => {
      if (prev.size === 0) return prev;
      const childIdSet = new Set(folderChildren.map((c) => c.ipnsName));
      const pruned = new Set([...prev].filter((id) => childIdSet.has(id)));
      if (pruned.size === prev.size) return prev;
      return pruned;
    });
  }, [folderChildren]);

  // Clear selection on navigation
  useEffect(() => {
    setSelectedIds(new Set());
  }, [currentShareId, breadcrumbs]);

  // Batch move dialog state
  const [batchMoveDialogOpen, setBatchMoveDialogOpen] = useState(false);
  const [batchMoveItems_, setBatchMoveItems_] = useState<SealedChildRef[]>([]);

  const handleBatchMoveClick = useCallback(() => {
    if (selectedItems.length === 0) return;
    setBatchMoveItems_([...selectedItems]);
    setBatchMoveDialogOpen(true);
  }, [selectedItems]);

  // Inline rename state
  const [renamingItem, setRenamingItem] = useState<SealedChildRef | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const renameInputRef = useRef<HTMLInputElement>(null);

  const isWritable = permission === 'write';
  // A DIRECT single-file share (root kind: 'file') — the text editor recovers
  // content via onLoadSharedFileContent (node/v3 read chain) instead of the
  // shared-FOLDER path's folderKey + downloadFileFromIpns (68.1-32).
  const isSingleFileShare = currentView === 'file';

  // Context menu handlers for folder view
  const handleContextMenu = useCallback(
    (event: MouseEvent, item: SealedChildRef) => {
      contextMenu.show(event, item);
      setContextShareId(null);
    },
    [contextMenu]
  );

  // Context menu for top-level shared items
  const handleSharedItemContextMenu = useCallback(
    (event: MouseEvent, item: SealedChildRef, shareId: string) => {
      contextMenu.show(event, item);
      setContextShareId(shareId);
    },
    [contextMenu]
  );

  const handleDownload = useCallback(async () => {
    const item = contextMenu.item;
    if (!item) return;
    // In list view, context menu download navigates to share first
    if (currentView === 'list' && contextShareId) {
      await navigateToShare(contextShareId);
      return;
    }
    await downloadSharedFile(item);
  }, [contextMenu.item, downloadSharedFile, currentView, contextShareId, navigateToShare]);

  const handleDetailsClick = useCallback(() => {
    if (contextMenu.item) {
      setDetailsDialog({ open: true, item: contextMenu.item });
    }
  }, [contextMenu.item]);

  const handleEditClick = useCallback(() => {
    if (contextMenu.item) {
      setEditorDialog({ open: true, item: contextMenu.item });
    }
  }, [contextMenu.item]);

  const handlePreviewClick = useCallback(() => {
    const item = contextMenu.item;
    if (!item) return;
    const name = item.name;
    if (isTextFile(name)) {
      setEditorDialog({ open: true, item });
    } else if (isImageFile(name)) {
      setImagePreviewDialog({ open: true, item });
    } else if (isPdfFile(name)) {
      setPdfPreviewDialog({ open: true, item });
    } else if (isAudioFile(name)) {
      setAudioPlayerDialog({ open: true, item });
    } else if (isVideoFile(name)) {
      setVideoPlayerDialog({ open: true, item });
    }
  }, [contextMenu.item]);

  const handleHide = useCallback(async () => {
    if (contextShareId) {
      await hideSharedItem(contextShareId);
    }
  }, [contextShareId, hideSharedItem]);

  // -------------------------------------------------------------------------
  // Write action handlers
  // -------------------------------------------------------------------------

  const handleUploadClick = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  const handleFileSelected = useCallback(
    async (event: React.ChangeEvent<HTMLInputElement>) => {
      const files = event.target.files;
      if (!files || files.length === 0) return;

      for (let i = 0; i < files.length; i++) {
        await uploadFile(files[i]);
      }

      // Reset input so the same file can be re-uploaded
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    },
    [uploadFile]
  );

  const handleCreateFolderClick = useCallback(() => {
    setShowNewFolderInput(true);
    setNewFolderName('');
    // Focus the input after React renders it
    setTimeout(() => newFolderInputRef.current?.focus(), 0);
  }, []);

  const handleCreateFolderSubmit = useCallback(async () => {
    const name = newFolderName.trim();
    if (!name) {
      setShowNewFolderInput(false);
      return;
    }

    await createFolder(name);
    setShowNewFolderInput(false);
    setNewFolderName('');
  }, [newFolderName, createFolder]);

  const handleCreateFolderKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleCreateFolderSubmit();
      } else if (e.key === 'Escape') {
        setShowNewFolderInput(false);
        setNewFolderName('');
      }
    },
    [handleCreateFolderSubmit]
  );

  // Context menu rename handler
  const handleRename = useCallback(() => {
    const item = contextMenu.item;
    if (!item) return;
    setRenamingItem(item);
    setRenameValue(item.name);
    contextMenu.hide();
    setTimeout(() => renameInputRef.current?.focus(), 0);
  }, [contextMenu]);

  const handleRenameSubmit = useCallback(async () => {
    if (!renamingItem) return;
    const name = renameValue.trim();
    if (!name || name === renamingItem.name) {
      setRenamingItem(null);
      return;
    }

    await renameItem(renamingItem, name);
    setRenamingItem(null);
    setRenameValue('');
  }, [renamingItem, renameValue, renameItem]);

  const handleRenameKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleRenameSubmit();
      } else if (e.key === 'Escape') {
        setRenamingItem(null);
        setRenameValue('');
      }
    },
    [handleRenameSubmit]
  );

  // Context menu delete handler
  const handleDelete = useCallback(async () => {
    const item = contextMenu.item;
    if (!item) return;
    await deleteItem(item);
  }, [contextMenu.item, deleteItem]);

  // Drag-and-drop handlers — always preventDefault to avoid browser navigation
  const handleDragOver = useCallback(
    (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      if (!isWritable) return;
      setIsDragOver(true);
    },
    [isWritable]
  );

  const handleDragLeave = useCallback(
    (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      if (!isWritable) return;
      setIsDragOver(false);
    },
    [isWritable]
  );

  const handleDrop = useCallback(
    async (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);
      if (!isWritable) return;

      const files = e.dataTransfer.files;
      if (!files || files.length === 0) return;

      for (let i = 0; i < files.length; i++) {
        await uploadFile(files[i]);
      }
    },
    [isWritable, uploadFile]
  );

  // Auto-open text editor when entering a writable file share view
  useEffect(() => {
    if (currentView === 'file' && currentShareId) {
      const shareItem = sharedItems.find((s) => s.share.shareId === currentShareId);
      if (shareItem && isTextFile(shareItem.share.itemName)) {
        // Synthesize a SealedChildRef for the text editor dialog. The single-file
        // editor recovers content via onLoadSharedFileContent (node/v3 read
        // chain, path []) — NOT readKeySealed, which stays an inert '' stub here
        // (68.1-32; unlike the shared-FOLDER path, a direct single-file share
        // has no parent read-body to source a real readKeySealed from).
        const fakeChildRef: SealedChildRef = {
          name: shareItem.share.itemName,
          ipnsName: shareItem.share.ipnsName,
          generation: 0,
          versionFloor: 0n,
          readKeySealed: '',
        };
        setEditorDialog({ open: true, item: fakeChildRef });
      } else {
        // Non-text files: download and return to list
        if (shareItem) {
          // Synthesize a SealedChildRef for download
          const fakeChildRef: SealedChildRef = {
            name: shareItem.share.itemName,
            ipnsName: shareItem.share.ipnsName,
            generation: 0,
            versionFloor: 0n,
            readKeySealed: '',
          };
          downloadSharedFile(fakeChildRef).finally(() => navigateToRoot());
        }
      }
    }
  }, [currentView, currentShareId, sharedItems, downloadSharedFile, navigateToRoot]);

  // Render top-level shared list
  if (currentView === 'list') {
    return (
      <div className="file-browser-content shared-browser">
        {/* Toolbar with breadcrumbs */}
        <div className="file-browser-toolbar">
          <nav className="breadcrumb-nav" aria-label="Current location" data-testid="breadcrumbs">
            <span className="breadcrumb-prefix">~</span>
            <span className="breadcrumb-separator">/</span>
            <span className="breadcrumb-item breadcrumb-item--current" aria-current="page">
              shared
            </span>
          </nav>
        </div>

        {/* Loading state */}
        {isLoading && (
          <div className="file-browser-loading">
            <span className="file-browser-loading-spinner">{'// loading shared items...'}</span>
          </div>
        )}

        {/* Error state */}
        {error && (
          <div className="shared-error" role="alert">
            <span>
              {'// ERROR: '}
              {error}
            </span>
          </div>
        )}

        {/* Empty state */}
        {!isLoading && sharedItems.length === 0 && !error && (
          <div className="empty-state" data-testid="shared-empty-state">
            <div className="empty-state-content">
              <pre className="empty-state-ascii" aria-hidden="true">
                {sharedEmptyArt}
              </pre>
              <p className="empty-state-text">{'// NO SHARED ITEMS'}</p>
              <p className="empty-state-hint">
                ask others to share files using your public key from Settings
              </p>
            </div>
          </div>
        )}

        {/* Shared items list */}
        {!isLoading && sharedItems.length > 0 && (
          <div className="file-list" role="grid">
            {/* Header row */}
            <div className="file-list-header" role="row">
              <div className="file-list-header-name" role="columnheader">
                [NAME]
              </div>
              <div className="file-list-header-shared-by" role="columnheader">
                [SHARED BY]
              </div>
              <div className="file-list-header-date" role="columnheader">
                [DATE]
              </div>
            </div>

            {/* Item rows */}
            <div className="file-list-body" role="rowgroup">
              {sharedItems.map((sharedItem) => (
                <SharedListRow
                  key={sharedItem.share.shareId}
                  sharedItem={sharedItem}
                  onOpen={() => navigateToShare(sharedItem.share.shareId)}
                  onContextMenu={(e) => {
                    const fakeChildRef: SealedChildRef = {
                      name: sharedItem.share.itemName,
                      ipnsName: sharedItem.share.ipnsName,
                      generation: 0,
                      versionFloor: 0n,
                      readKeySealed: '',
                    };
                    handleSharedItemContextMenu(e, fakeChildRef, sharedItem.share.shareId);
                  }}
                />
              ))}
            </div>
          </div>
        )}

        {/* Read-only context menu */}
        {contextMenu.visible && contextMenu.item && (
          <ContextMenu
            x={contextMenu.x}
            y={contextMenu.y}
            item={contextMenu.item}
            resolvedChildren={resolvedChildren}
            selectedCount={1}
            onClose={contextMenu.hide}
            // List view items are raw top-level shares (file or folder) with no
            // resolved-kind data available; download here navigates to the share
            // for both kinds (see handleDownload), so no kind gate is needed.
            onDownload={handleDownload}
            onRename={() => {}}
            onDelete={() => {}}
            onDetails={handleDetailsClick}
            readOnly
            onHide={contextShareId ? handleHide : undefined}
          />
        )}

        {/* Details dialog */}
        <DetailsDialog
          open={detailsDialog.open}
          onClose={() => setDetailsDialog({ open: false, item: null })}
          item={detailsDialog.item}
          resolvedChildren={resolvedChildren}
          folderKey={null}
          parentFolderId=""
        />
      </div>
    );
  }

  // Render folder view (inside a shared folder)
  const sortedChildren = sortItems(folderChildren, resolvedByIpnsName);
  const hasChildren = folderChildren.length > 0;

  return (
    <div
      className={`file-browser-content shared-browser${isDragOver ? ' shared-drag-over' : ''}`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* Toolbar with breadcrumbs and write actions */}
      <div className="file-browser-toolbar">
        <nav className="breadcrumb-nav" aria-label="Current location" data-testid="breadcrumbs">
          <span className="breadcrumb-prefix">~</span>
          <span className="breadcrumb-separator">/</span>
          <button type="button" className="breadcrumb-item" onClick={navigateToRoot}>
            shared
          </button>
          {breadcrumbs.map((crumb, index) => {
            const isLast = index === breadcrumbs.length - 1;
            return (
              <span key={crumb.id}>
                <span className="breadcrumb-separator">/</span>
                {isLast ? (
                  <span className="breadcrumb-item breadcrumb-item--current" aria-current="page">
                    {crumb.name.toLowerCase()}
                  </span>
                ) : (
                  <button
                    type="button"
                    className="breadcrumb-item"
                    onClick={() => navigateToBreadcrumb(breadcrumbs.indexOf(crumb))}
                  >
                    {crumb.name.toLowerCase()}
                  </button>
                )}
              </span>
            );
          })}
        </nav>

        {/* Write toolbar -- only visible for write shares */}
        {isWritable && (
          <div className="file-browser-actions">
            <button
              type="button"
              className="toolbar-btn toolbar-btn--primary"
              onClick={handleUploadClick}
            >
              {'--upload'}
            </button>
            <button
              type="button"
              className="toolbar-btn toolbar-btn--primary"
              onClick={handleCreateFolderClick}
            >
              {'--mkdir'}
            </button>
            {/* Hidden file input for upload */}
            <input
              ref={fileInputRef}
              type="file"
              multiple
              style={{ display: 'none' }}
              onChange={handleFileSelected}
            />
          </div>
        )}
      </div>

      {/* Selection action bar -- shown when items are selected in write shares.
          Only Move is wired for shared multi-select (phase 49); Download/Delete
          are intentionally omitted so the bar renders no no-op buttons. */}
      {isWritable && multiSelectActive && (
        <SelectionActionBar
          selectedItems={selectedItems}
          resolvedChildren={resolvedChildren}
          isLoading={isLoading}
          onClearSelection={clearSelection}
          onMove={handleBatchMoveClick}
        />
      )}

      {/* Inline new folder input */}
      {showNewFolderInput && (
        <div className="shared-inline-input">
          <span className="shared-inline-input-label">{'> mkdir '}</span>
          <input
            ref={newFolderInputRef}
            type="text"
            className="shared-inline-input-field"
            value={newFolderName}
            onChange={(e) => setNewFolderName(e.target.value)}
            onKeyDown={handleCreateFolderKeyDown}
            onBlur={handleCreateFolderSubmit}
            placeholder="folder-name"
            aria-label="New folder name"
          />
        </div>
      )}

      {/* Loading state */}
      {isLoading && (
        <div className="file-browser-loading">
          <span className="file-browser-loading-spinner">{'// loading...'}</span>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="shared-error" role="alert">
          <span>
            {'// ERROR: '}
            {error}
          </span>
        </div>
      )}

      {/* File list -- the [..] PARENT_DIR row must always render while inside a
          shared folder (even when empty), otherwise a freshly-created/empty
          shared folder leaves no way back up and no `.file-list-row--parent`
          anchor for callers that navigate in before anything has been
          uploaded (SC#5 desync repro: grantee navigates into an empty shared
          folder to upload the very first file). */}
      {!isLoading && !error && (
        <div className="file-list" role="grid">
          {/* Header row */}
          <div className="file-list-header" role="row">
            <div className="file-list-header-name" role="columnheader">
              [NAME]
            </div>
            <div className="file-list-header-size" role="columnheader">
              [SIZE]
            </div>
            <div className="file-list-header-date" role="columnheader">
              [MODIFIED]
            </div>
          </div>

          <div className="file-list-body" role="rowgroup">
            {/* [..] PARENT_DIR row */}
            <div
              className="file-list-row file-list-row--parent"
              role="row"
              tabIndex={0}
              onDoubleClick={navigateUp}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  navigateUp();
                }
              }}
            >
              <div className="file-list-cell file-list-cell-name" role="gridcell">
                <span className="file-icon">{'<-'}</span>
                <span className="file-name">[..] PARENT_DIR</span>
              </div>
              <div className="file-list-cell file-list-cell-size" role="gridcell">
                --
              </div>
              <div className="file-list-cell file-list-cell-date" role="gridcell">
                --
              </div>
            </div>

            {hasChildren ? (
              /* File/folder rows */
              sortedChildren.map((item) => (
                <SharedFolderRow
                  key={item.ipnsName}
                  item={item}
                  resolved={resolvedByIpnsName.get(item.ipnsName)}
                  resolvedByIpnsName={resolvedByIpnsName}
                  permission={permission}
                  isRenaming={renamingItem?.ipnsName === item.ipnsName}
                  renameValue={renameValue}
                  renameInputRef={renameInputRef}
                  onRenameChange={setRenameValue}
                  onRenameKeyDown={handleRenameKeyDown}
                  onRenameSubmit={handleRenameSubmit}
                  onContextMenu={(e) => handleContextMenu(e, item)}
                  isSelected={selectedIds.has(item.ipnsName)}
                  onSelect={(e) => handleSelect(item.ipnsName, e)}
                  onDoubleClick={() => {
                    // D-02: kind classification -- files no-op on double-click (open is a
                    // context-menu action: Preview/Edit/Download), mirroring FileListItem.tsx.
                    // 68.2-15: `item` is a raw ref; classify against the resolved listing.
                    if (!isFileRefResolved(item, resolvedByIpnsName)) {
                      navigateToSubfolder(item.ipnsName, item.name);
                    }
                  }}
                  onMoveItemTo={
                    isWritable
                      ? (destFolderId, destIpnsName, draggedItems) => {
                          // Route by what was actually dragged. Resolve by ipnsName.
                          const draggedIds = new Set(draggedItems.map((d) => d.id));
                          const movedItems = sortedChildren.filter((c) =>
                            draggedIds.has(c.ipnsName)
                          );
                          if (movedItems.length === 0) return;
                          if (movedItems.length > 1) {
                            void batchMoveItems(
                              movedItems,
                              destFolderId,
                              destIpnsName,
                              clearSelection
                            );
                          } else {
                            void moveItem(movedItems[0], destFolderId, destIpnsName);
                          }
                        }
                      : undefined
                  }
                  selectedItems={selectedItems}
                />
              ))
            ) : (
              /* Empty folder -- still inside the [..] PARENT_DIR-anchored file-list
                 body so navigating back up remains possible (D-08 fix). */
              <div className="empty-state empty-state--inline" data-testid="shared-empty-folder">
                <div className="empty-state-content">
                  <pre className="empty-state-ascii" aria-hidden="true">
                    {sharedEmptyArt}
                  </pre>
                  <p className="empty-state-text">{'// EMPTY SHARED FOLDER'}</p>
                  <p className="empty-state-hint">
                    {isWritable
                      ? 'drag files here or use --upload'
                      : 'this shared folder has no contents'}
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Context menu -- conditional readOnly based on permission */}
      {contextMenu.visible && contextMenu.item && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          item={contextMenu.item}
          selectedCount={1}
          onClose={contextMenu.hide}
          // D-02: Download is a file-only action, gated on kind. 68.2-15: classify the
          // raw `contextMenu.item` against the resolved listing (ContextMenu itself also
          // gates on isFile via the resolvedChildren prop below — Analog A).
          resolvedChildren={resolvedChildren}
          onDownload={
            isFileRefResolved(contextMenu.item, resolvedByIpnsName) ? handleDownload : undefined
          }
          onEdit={isTextFile(contextMenu.item.name) ? handleEditClick : undefined}
          onPreview={isPreviewableFile(contextMenu.item.name) ? handlePreviewClick : undefined}
          onRename={isWritable ? handleRename : () => {}}
          onDelete={isWritable ? handleDelete : () => {}}
          onMove={isWritable ? () => handleMoveClick(contextMenu.item!) : undefined}
          onDetails={handleDetailsClick}
          readOnly={permission !== 'write'}
        />
      )}

      {/* Move dialog -- shared subtree picker (folder view only) */}
      <SharedMoveDialog
        open={!!moveDialogItem}
        item={moveDialogItem}
        resolvedByIpnsName={resolvedByIpnsName}
        currentFolderId={breadcrumbs[breadcrumbs.length - 1]?.id ?? currentShareId ?? ''}
        shareId={currentShareId}
        onClose={() => setMoveDialogItem(null)}
        onConfirm={(destFolderId, destIpnsName) => {
          if (moveDialogItem) {
            void moveItem(moveDialogItem, destFolderId, destIpnsName);
          }
          setMoveDialogItem(null);
        }}
      />

      {/* Batch move dialog -- opened from SelectionActionBar */}
      <SharedMoveDialog
        open={batchMoveDialogOpen}
        item={null}
        items={batchMoveItems_}
        resolvedByIpnsName={resolvedByIpnsName}
        currentFolderId={breadcrumbs[breadcrumbs.length - 1]?.id ?? currentShareId ?? ''}
        shareId={currentShareId}
        onClose={() => {
          setBatchMoveDialogOpen(false);
          setBatchMoveItems_([]);
        }}
        onConfirm={(destFolderId, destIpnsName) => {
          void batchMoveItems(batchMoveItems_, destFolderId, destIpnsName, clearSelection);
          setBatchMoveDialogOpen(false);
          setBatchMoveItems_([]);
        }}
      />

      {/* Details dialog */}
      <DetailsDialog
        open={detailsDialog.open}
        onClose={() => setDetailsDialog({ open: false, item: null })}
        item={detailsDialog.item}
        resolvedChildren={resolvedChildren}
        folderKey={folderKey}
        parentFolderId=""
      />

      {/* Text viewer dialog (read-only for read shares, editable for write shares) */}
      <TextEditorDialog
        open={editorDialog.open}
        onClose={() => {
          setEditorDialog({ open: false, item: null });
          // If viewing a standalone file share, go back to list on close
          if (currentView === 'file') {
            navigateToRoot();
          }
        }}
        item={editorDialog.item ?? null}
        parentFolderId=""
        folderKey={folderKey}
        readOnly={!isWritable}
        shareId={currentShareId}
        onLoadSharedFileContent={isSingleFileShare ? loadSharedFileContent : undefined}
        onSaveSharedFile={
          isWritable ? (isSingleFileShare ? saveSharedSingleFile : updateSharedFile) : undefined
        }
      />

      {/* Image preview dialog */}
      <ImagePreviewDialog
        open={imagePreviewDialog.open}
        onClose={() => setImagePreviewDialog({ open: false, item: null })}
        item={imagePreviewDialog.item ?? null}
        folderKey={folderKey}
      />

      {/* PDF preview dialog */}
      <PdfPreviewDialog
        open={pdfPreviewDialog.open}
        onClose={() => setPdfPreviewDialog({ open: false, item: null })}
        item={pdfPreviewDialog.item ?? null}
        folderKey={folderKey}
      />

      {/* Audio player dialog */}
      <AudioPlayerDialog
        open={audioPlayerDialog.open}
        onClose={() => setAudioPlayerDialog({ open: false, item: null })}
        item={audioPlayerDialog.item ?? null}
        folderKey={folderKey}
      />

      {/* Video player dialog */}
      <VideoPlayerDialog
        open={videoPlayerDialog.open}
        onClose={() => setVideoPlayerDialog({ open: false, item: null })}
        item={videoPlayerDialog.item ?? null}
        folderKey={folderKey}
      />
    </div>
  );
}
