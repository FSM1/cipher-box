/**
 * SharedFileBrowser -- Read-only file browser for shared content.
 *
 * Shows items shared with the current user at ~/shared.
 * - Top-level: flat list of received shares with SHARED BY column
 * - Inside folder: standard file list with [RO] badges, no write actions
 * - Context menu: Download, Preview, Details, Hide only
 * - No upload, no create folder, no rename, no move, no delete
 */

import { useState, useCallback, type MouseEvent } from 'react';
import type { FolderChild, FilePointer } from '@cipherbox/crypto';
import { useSharedNavigation, type SharedListItem } from '../../hooks/useSharedNavigation';
import { useContextMenu } from '../../hooks/useContextMenu';
import { ContextMenu } from './ContextMenu';
import { DetailsDialog } from './DetailsDialog';
import { ImagePreviewDialog } from './ImagePreviewDialog';
import { PdfPreviewDialog } from './PdfPreviewDialog';
import { AudioPlayerDialog } from './AudioPlayerDialog';
import { VideoPlayerDialog } from './VideoPlayerDialog';
import '../../styles/shared-browser.css';

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

/** Extensions recognized as PDF files. */
const PDF_EXTENSIONS = new Set(['.pdf']);

/** Extensions recognized as playable audio files. */
const AUDIO_EXTENSIONS = new Set(['.mp3', '.wav', '.ogg', '.m4a', '.flac']);

/** Extensions recognized as playable video files. */
const VIDEO_EXTENSIONS = new Set(['.mp4', '.webm', '.mov', '.mkv']);

function isImageFile(name: string): boolean {
  const lower = name.toLowerCase();
  const lastDot = lower.lastIndexOf('.');
  if (lastDot === -1) return false;
  return IMAGE_EXTENSIONS.has(lower.slice(lastDot));
}

function isPdfFile(name: string): boolean {
  const lower = name.toLowerCase();
  const lastDot = lower.lastIndexOf('.');
  if (lastDot === -1) return false;
  return PDF_EXTENSIONS.has(lower.slice(lastDot));
}

function isAudioFile(name: string): boolean {
  const lower = name.toLowerCase();
  const lastDot = lower.lastIndexOf('.');
  if (lastDot === -1) return false;
  return AUDIO_EXTENSIONS.has(lower.slice(lastDot));
}

function isVideoFile(name: string): boolean {
  const lower = name.toLowerCase();
  const lastDot = lower.lastIndexOf('.');
  if (lastDot === -1) return false;
  return VIDEO_EXTENSIONS.has(lower.slice(lastDot));
}

function isPreviewableFile(name: string): boolean {
  return isImageFile(name) || isPdfFile(name) || isAudioFile(name) || isVideoFile(name);
}

function isFilePointer(item: FolderChild): item is FilePointer {
  return item.type === 'file';
}

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
    folderKey,
    breadcrumbs,
    isLoading,
    error,
    navigateToShare,
    navigateToSubfolder,
    navigateUp,
    navigateToRoot,
    downloadSharedFile,
    hideSharedItem,
  } = useSharedNavigation();

  const contextMenu = useContextMenu();

  // Dialog states
  const [detailsDialog, setDetailsDialog] = useState<DialogState>({ open: false, item: null });
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
    await downloadSharedFile(item);
  }, [contextMenu.item, downloadSharedFile]);

  const handleDetailsClick = useCallback(() => {
    if (contextMenu.item) {
      setDetailsDialog({ open: true, item: contextMenu.item });
    }
  }, [contextMenu.item]);

  const handlePreviewClick = useCallback(() => {
    const item = contextMenu.item;
    if (!item || !isFilePointer(item)) return;
    const name = item.name;
    if (isImageFile(name)) {
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
        {!isLoading && sharedItems.length === 0 && (
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
    <div className="file-browser-content shared-browser">
      {/* Toolbar with breadcrumbs */}
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
                    onClick={() => {
                      // Navigate to this breadcrumb level
                      const crumbIndex = breadcrumbs.indexOf(crumb);
                      // Pop nav stack to this level
                      const popsNeeded = breadcrumbs.length - 1 - crumbIndex;
                      for (let i = 0; i < popsNeeded; i++) {
                        navigateUp();
                      }
                    }}
                  >
                    {crumb.name.toLowerCase()}
                  </button>
                )}
              </span>
            );
          })}
        </nav>
      </div>

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
              onClick={navigateUp}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  navigateUp();
                }
              }}
              onDoubleClick={navigateUp}
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
                onOpen={() => {
                  if (item.type === 'folder') {
                    navigateToSubfolder(item.id, item.name);
                  }
                }}
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
      {!isLoading && !hasChildren && (
        <div className="empty-state" data-testid="shared-empty-folder">
          <div className="empty-state-content">
            <pre className="empty-state-ascii" aria-hidden="true">
              {sharedEmptyArt}
            </pre>
            <p className="empty-state-text">{'// EMPTY SHARED FOLDER'}</p>
            <p className="empty-state-hint">this shared folder has no contents</p>
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
          onPreview={
            contextMenu.item.type === 'file' && isPreviewableFile(contextMenu.item.name)
              ? handlePreviewClick
              : undefined
          }
          onRename={() => {}}
          onDelete={() => {}}
          onDetails={handleDetailsClick}
          readOnly
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

  return (
    <div
      className="file-list-row shared-list-row"
      role="row"
      tabIndex={0}
      onClick={onOpen}
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
        <span className="shared-ro-badge">[RO]</span>
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
 */
function SharedFolderRow({
  item,
  onOpen,
  onContextMenu,
  onDoubleClick,
}: {
  item: FolderChild;
  onOpen: () => void;
  onContextMenu: (e: MouseEvent) => void;
  onDoubleClick: () => void;
}) {
  const isFolder = item.type === 'folder';
  const icon = isFolder ? '\uD83D\uDCC1' : '\uD83D\uDCC4';
  const date = item.modifiedAt ? new Date(item.modifiedAt).toLocaleDateString() : '--';

  return (
    <div
      className="file-list-row"
      role="row"
      tabIndex={0}
      onClick={onOpen}
      onDoubleClick={onDoubleClick}
      onContextMenu={(e) => {
        e.preventDefault();
        onContextMenu(e);
      }}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onDoubleClick();
        }
      }}
    >
      <div className="file-list-cell file-list-cell-name" role="gridcell">
        <span className="file-icon">{icon}</span>
        <span className="file-name">
          {item.name}
          {isFolder ? '/' : ''}
        </span>
        <span className="shared-ro-badge">[RO]</span>
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
