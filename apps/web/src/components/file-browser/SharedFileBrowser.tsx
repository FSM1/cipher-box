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

import { useState, useCallback, useRef, type MouseEvent, type DragEvent } from 'react';
import type { FolderChild } from '@cipherbox/core';
import { useSharedNavigation, type SharedListItem } from '../../hooks/useSharedNavigation';
import { useContextMenu } from '../../hooks/useContextMenu';
import {
  isFilePointer,
  isTextFile,
  isImageFile,
  isPdfFile,
  isAudioFile,
  isVideoFile,
  isPreviewableFile,
} from '../../utils/fileTypes';
import { ContextMenu } from './ContextMenu';
import { DetailsDialog } from './DetailsDialog';
import { ImagePreviewDialog } from './ImagePreviewDialog';
import { PdfPreviewDialog } from './PdfPreviewDialog';
import { AudioPlayerDialog } from './AudioPlayerDialog';
import { VideoPlayerDialog } from './VideoPlayerDialog';
import { TextEditorDialog } from './TextEditorDialog';
import '../../styles/shared-browser.css';

/**
 * Truncate a public key for display: 0x{first4}...{last4}
 */
function truncatePubkey(pubkey: string): string {
  if (pubkey.length <= 12) return pubkey;
  const hex = pubkey.startsWith('0x') ? pubkey.slice(2) : pubkey;
  return `0x${hex.slice(0, 4)}...${hex.slice(-4)}`;
}

/**
 * Sort items: folders first, then files, both alphabetically.
 */
function sortItems(items: FolderChild[]): FolderChild[] {
  return [...items].sort((a, b) => {
    if (a.type === 'folder' && b.type !== 'folder') return -1;
    if (a.type !== 'folder' && b.type === 'folder') return 1;
    return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
  });
}

type DialogState = {
  open: boolean;
  item: FolderChild | null;
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
    hideSharedItem,
    uploadFile,
    createFolder,
    renameItem,
    deleteItem,
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

  // Inline rename state
  const [renamingItem, setRenamingItem] = useState<FolderChild | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const renameInputRef = useRef<HTMLInputElement>(null);

  const isWritable = permission === 'write';

  // Context menu handlers for folder view
  const handleContextMenu = useCallback(
    (event: MouseEvent, item: FolderChild) => {
      contextMenu.show(event, item);
      setContextShareId(null);
    },
    [contextMenu]
  );

  // Context menu for top-level shared items
  const handleSharedItemContextMenu = useCallback(
    (event: MouseEvent, item: FolderChild, shareId: string) => {
      contextMenu.show(event, item);
      setContextShareId(shareId);
    },
    [contextMenu]
  );

  const handleDownload = useCallback(async () => {
    const item = contextMenu.item;
    if (!item || !isFilePointer(item)) return;

    // In list view, context menu download needs to use navigateToShare
    // because downloadSharedFile requires currentShareId/folderKey (null in list view)
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
    if (!item || !isFilePointer(item)) return;
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

  // Drag-and-drop handlers for write shares
  const handleDragOver = useCallback(
    (e: DragEvent) => {
      if (!isWritable) return;
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(true);
    },
    [isWritable]
  );

  const handleDragLeave = useCallback(
    (e: DragEvent) => {
      if (!isWritable) return;
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);
    },
    [isWritable]
  );

  const handleDrop = useCallback(
    async (e: DragEvent) => {
      if (!isWritable) return;
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);

      const files = e.dataTransfer.files;
      if (!files || files.length === 0) return;

      for (let i = 0; i < files.length; i++) {
        await uploadFile(files[i]);
      }
    },
    [isWritable, uploadFile]
  );

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
                    // Create a synthetic FolderChild for context menu
                    const fakeItem: FolderChild =
                      sharedItem.share.itemType === 'folder'
                        ? {
                            type: 'folder' as const,
                            id: sharedItem.share.shareId,
                            name: sharedItem.share.itemName,
                            ipnsName: sharedItem.share.ipnsName,
                            ipnsPrivateKeyEncrypted: '',
                            folderKeyEncrypted: '',
                            createdAt: Date.parse(sharedItem.share.createdAt),
                            modifiedAt: Date.parse(sharedItem.share.createdAt),
                          }
                        : {
                            type: 'file' as const,
                            id: sharedItem.share.shareId,
                            name: sharedItem.share.itemName,
                            fileMetaIpnsName: sharedItem.share.ipnsName,
                            createdAt: Date.parse(sharedItem.share.createdAt),
                            modifiedAt: Date.parse(sharedItem.share.createdAt),
                          };
                    handleSharedItemContextMenu(e, fakeItem, sharedItem.share.shareId);
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
            selectedCount={1}
            onClose={contextMenu.hide}
            onDownload={contextMenu.item.type === 'file' ? handleDownload : undefined}
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
          folderKey={null}
          parentFolderId=""
        />
      </div>
    );
  }

  // Render folder view (inside a shared folder)
  const sortedChildren = sortItems(folderChildren);
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

      {/* File list */}
      {!isLoading && hasChildren && (
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

          {/* [..] PARENT_DIR row */}
          <div className="file-list-body" role="rowgroup">
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

            {/* File/folder rows */}
            {sortedChildren.map((item) => (
              <SharedFolderRow
                key={item.id}
                item={item}
                permission={permission}
                isRenaming={renamingItem?.id === item.id}
                renameValue={renameValue}
                renameInputRef={renameInputRef}
                onRenameChange={setRenameValue}
                onRenameKeyDown={handleRenameKeyDown}
                onRenameSubmit={handleRenameSubmit}
                onContextMenu={(e) => handleContextMenu(e, item)}
                onDoubleClick={() => {
                  if (item.type === 'folder') {
                    navigateToSubfolder(item.id, item.name);
                  } else if (isFilePointer(item)) {
                    downloadSharedFile(item);
                  }
                }}
              />
            ))}
          </div>
        </div>
      )}

      {/* Empty folder */}
      {!isLoading && !hasChildren && !error && (
        <div className="empty-state" data-testid="shared-empty-folder">
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

      {/* Context menu -- conditional readOnly based on permission */}
      {contextMenu.visible && contextMenu.item && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          item={contextMenu.item}
          selectedCount={1}
          onClose={contextMenu.hide}
          onDownload={contextMenu.item.type === 'file' ? handleDownload : undefined}
          onEdit={
            contextMenu.item.type === 'file' && isTextFile(contextMenu.item.name)
              ? handleEditClick
              : undefined
          }
          onPreview={
            contextMenu.item.type === 'file' && isPreviewableFile(contextMenu.item.name)
              ? handlePreviewClick
              : undefined
          }
          onRename={isWritable ? handleRename : () => {}}
          onDelete={isWritable ? handleDelete : () => {}}
          onDetails={handleDetailsClick}
          readOnly={permission !== 'write'}
        />
      )}

      {/* Details dialog */}
      <DetailsDialog
        open={detailsDialog.open}
        onClose={() => setDetailsDialog({ open: false, item: null })}
        item={detailsDialog.item}
        folderKey={folderKey}
        parentFolderId=""
      />

      {/* Text viewer dialog (read-only for read shares, editable for write shares) */}
      <TextEditorDialog
        open={editorDialog.open}
        onClose={() => setEditorDialog({ open: false, item: null })}
        item={editorDialog.item && isFilePointer(editorDialog.item) ? editorDialog.item : null}
        parentFolderId=""
        folderKey={folderKey}
        readOnly={!isWritable}
        shareId={currentShareId}
      />

      {/* Image preview dialog */}
      <ImagePreviewDialog
        open={imagePreviewDialog.open}
        onClose={() => setImagePreviewDialog({ open: false, item: null })}
        item={
          imagePreviewDialog.item && isFilePointer(imagePreviewDialog.item)
            ? imagePreviewDialog.item
            : null
        }
        folderKey={folderKey}
        shareId={currentShareId}
      />

      {/* PDF preview dialog */}
      <PdfPreviewDialog
        open={pdfPreviewDialog.open}
        onClose={() => setPdfPreviewDialog({ open: false, item: null })}
        item={
          pdfPreviewDialog.item && isFilePointer(pdfPreviewDialog.item)
            ? pdfPreviewDialog.item
            : null
        }
        folderKey={folderKey}
        shareId={currentShareId}
      />

      {/* Audio player dialog */}
      <AudioPlayerDialog
        open={audioPlayerDialog.open}
        onClose={() => setAudioPlayerDialog({ open: false, item: null })}
        item={
          audioPlayerDialog.item && isFilePointer(audioPlayerDialog.item)
            ? audioPlayerDialog.item
            : null
        }
        folderKey={folderKey}
        shareId={currentShareId}
      />

      {/* Video player dialog */}
      <VideoPlayerDialog
        open={videoPlayerDialog.open}
        onClose={() => setVideoPlayerDialog({ open: false, item: null })}
        item={
          videoPlayerDialog.item && isFilePointer(videoPlayerDialog.item)
            ? videoPlayerDialog.item
            : null
        }
        folderKey={folderKey}
        shareId={currentShareId}
      />
    </div>
  );
}

/**
 * Row component for the top-level shared items list.
 */
function SharedListRow({
  sharedItem,
  onOpen,
  onContextMenu,
}: {
  sharedItem: SharedListItem;
  onOpen: () => void;
  onContextMenu: (e: MouseEvent) => void;
}) {
  const { share } = sharedItem;
  const isFolder = share.itemType === 'folder';
  const icon = isFolder ? '\uD83D\uDCC1' : '\uD83D\uDCC4';
  const date = new Date(share.createdAt).toLocaleDateString();
  const isWrite = share.permission === 'write';

  return (
    <div
      className="file-list-row shared-list-row"
      role="row"
      tabIndex={0}
      onDoubleClick={onOpen}
      onContextMenu={(e) => {
        e.preventDefault();
        onContextMenu(e);
      }}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onOpen();
        }
      }}
    >
      <div className="file-list-cell file-list-cell-name" role="gridcell">
        <span className="file-icon">{icon}</span>
        <span className="file-name">
          {share.itemName}
          {isFolder ? '/' : ''}
        </span>
        {isWrite ? (
          <span className="shared-rw-badge">{'[RW]'}</span>
        ) : (
          <span className="shared-ro-badge">{'[RO]'}</span>
        )}
      </div>
      <div className="file-list-cell shared-by-cell" role="gridcell">
        {truncatePubkey(share.sharerPublicKey)}
      </div>
      <div className="file-list-cell file-list-cell-date" role="gridcell">
        {date}
      </div>
    </div>
  );
}

/**
 * Row component for items within a shared folder.
 * Shows [RW] or [RO] badge based on the share's permission level.
 * Supports inline renaming when isRenaming is true.
 */
function SharedFolderRow({
  item,
  permission,
  isRenaming,
  renameValue,
  renameInputRef,
  onRenameChange,
  onRenameKeyDown,
  onRenameSubmit,
  onContextMenu,
  onDoubleClick,
}: {
  item: FolderChild;
  permission: 'read' | 'write' | null;
  isRenaming: boolean;
  renameValue: string;
  renameInputRef: React.RefObject<HTMLInputElement>;
  onRenameChange: (value: string) => void;
  onRenameKeyDown: (e: React.KeyboardEvent) => void;
  onRenameSubmit: () => void;
  onContextMenu: (e: MouseEvent) => void;
  onDoubleClick: () => void;
}) {
  const isFolder = item.type === 'folder';
  const icon = isFolder ? '\uD83D\uDCC1' : '\uD83D\uDCC4';
  const date = item.modifiedAt ? new Date(item.modifiedAt).toLocaleDateString() : '--';
  const isWrite = permission === 'write';

  return (
    <div
      className="file-list-row"
      role="row"
      tabIndex={0}
      onDoubleClick={isRenaming ? undefined : onDoubleClick}
      onContextMenu={(e) => {
        e.preventDefault();
        onContextMenu(e);
      }}
      onKeyDown={(e) => {
        if (isRenaming) return;
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onDoubleClick();
        }
      }}
    >
      <div className="file-list-cell file-list-cell-name" role="gridcell">
        <span className="file-icon">{icon}</span>
        {isRenaming ? (
          <input
            ref={renameInputRef}
            type="text"
            className="shared-inline-rename-field"
            value={renameValue}
            onChange={(e) => onRenameChange(e.target.value)}
            onKeyDown={onRenameKeyDown}
            onBlur={onRenameSubmit}
            aria-label="Rename item"
          />
        ) : (
          <>
            <span className="file-name">
              {item.name}
              {isFolder ? '/' : ''}
            </span>
            {isWrite ? (
              <span className="shared-rw-badge">{'[RW]'}</span>
            ) : (
              <span className="shared-ro-badge">{'[RO]'}</span>
            )}
          </>
        )}
      </div>
      <div className="file-list-cell file-list-cell-size" role="gridcell">
        --
      </div>
      <div className="file-list-cell file-list-cell-date" role="gridcell">
        {date}
      </div>
    </div>
  );
}
