import { useCallback, useRef, type DragEvent, type MouseEvent, type TouchEvent } from 'react';
import type { FolderChild, FileEntry, FolderEntry } from '@cipherbox/crypto';
import { formatBytes, formatDate } from '../../utils/format';

/**
 * Long press duration in milliseconds for touch context menu.
 */
const LONG_PRESS_DURATION = 500;

type FileListItemProps = {
  /** The file or folder item to display */
  item: FolderChild;
  /** Whether this item is currently selected */
  isSelected: boolean;
  /** Parent folder ID (for drag data) */
  parentId: string;
  /** Callback when item is clicked */
  onSelect: (itemId: string) => void;
  /** Callback when folder is double-clicked to navigate into */
  onNavigate: (folderId: string) => void;
  /** Callback when right-click context menu is requested */
  onContextMenu: (event: MouseEvent, item: FolderChild) => void;
  /** Callback when drag starts */
  onDragStart: (event: DragEvent, item: FolderChild) => void;
};

/**
 * Type guard for folder entries.
 */
function isFolder(item: FolderChild): item is FolderEntry {
  return item.type === 'folder';
}

/**
 * Type guard for file entries.
 */
function isFile(item: FolderChild): item is FileEntry {
  return item.type === 'file';
}

/**
 * Get appropriate icon for item type.
 */
function getItemIcon(item: FolderChild): string {
  if (isFolder(item)) {
    return '📁';
  }

  // Simple file type detection by extension
  const name = item.name.toLowerCase();
  if (name.endsWith('.pdf')) return '📄';
  if (name.endsWith('.doc') || name.endsWith('.docx')) return '📝';
  if (name.endsWith('.xls') || name.endsWith('.xlsx')) return '📊';
  if (
    name.endsWith('.jpg') ||
    name.endsWith('.jpeg') ||
    name.endsWith('.png') ||
    name.endsWith('.gif')
  )
    return '🖼️';
  if (name.endsWith('.mp3') || name.endsWith('.wav') || name.endsWith('.flac')) return '🎵';
  if (name.endsWith('.mp4') || name.endsWith('.mov') || name.endsWith('.avi')) return '🎬';
  if (name.endsWith('.zip') || name.endsWith('.rar') || name.endsWith('.7z')) return '📦';

  return '📄';
}

/**
 * Single row in the file list.
 *
 * Displays file/folder with icon, name, size, and date.
 * Supports selection, navigation (for folders), context menu, and drag-drop.
 */
export function FileListItem({
  item,
  isSelected,
  parentId,
  onSelect,
  onNavigate,
  onContextMenu,
  onDragStart,
}: FileListItemProps) {
  // Ref for long press timer
  const longPressTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const touchStartPosRef = useRef<{ x: number; y: number } | null>(null);

  /**
   * Handle single click - select the item.
   */
  const handleClick = useCallback(() => {
    onSelect(item.id);
  }, [item.id, onSelect]);

  /**
   * Handle double click - navigate into folder.
   */
  const handleDoubleClick = useCallback(() => {
    if (isFolder(item)) {
      onNavigate(item.id);
    }
  }, [item, onNavigate]);

  /**
   * Handle context menu (right-click).
   */
  const handleContextMenu = useCallback(
    (e: MouseEvent) => {
      e.preventDefault();
      onContextMenu(e, item);
    },
    [item, onContextMenu]
  );

  /**
   * Handle drag start - serialize item data.
   */
  const handleDragStart = useCallback(
    (e: DragEvent) => {
      // Set drag data for move operations
      e.dataTransfer.setData(
        'application/json',
        JSON.stringify({
          id: item.id,
          type: item.type,
          parentId,
        })
      );
      e.dataTransfer.effectAllowed = 'move';
      onDragStart(e, item);
    },
    [item, parentId, onDragStart]
  );

  /**
   * Clear long press timer.
   */
  const clearLongPressTimer = useCallback(() => {
    if (longPressTimerRef.current) {
      clearTimeout(longPressTimerRef.current);
      longPressTimerRef.current = null;
    }
    touchStartPosRef.current = null;
  }, []);

  /**
   * Handle touch start - begin long press detection.
   */
  const handleTouchStart = useCallback(
    (e: TouchEvent) => {
      const touch = e.touches[0];
      if (!touch) return;

      // Store touch position for move detection
      touchStartPosRef.current = { x: touch.clientX, y: touch.clientY };

      // Start long press timer
      longPressTimerRef.current = setTimeout(() => {
        // Create synthetic mouse event for context menu
        const syntheticEvent = {
          preventDefault: () => {},
          clientX: touch.clientX,
          clientY: touch.clientY,
        } as unknown as MouseEvent;
        onContextMenu(syntheticEvent, item);
        clearLongPressTimer();
      }, LONG_PRESS_DURATION);
    },
    [item, onContextMenu, clearLongPressTimer]
  );

  /**
   * Handle touch move - cancel long press if moved too far.
   */
  const handleTouchMove = useCallback(
    (e: TouchEvent) => {
      if (!touchStartPosRef.current || !longPressTimerRef.current) return;

      const touch = e.touches[0];
      if (!touch) return;

      // Cancel if moved more than 10px
      const dx = Math.abs(touch.clientX - touchStartPosRef.current.x);
      const dy = Math.abs(touch.clientY - touchStartPosRef.current.y);
      if (dx > 10 || dy > 10) {
        clearLongPressTimer();
      }
    },
    [clearLongPressTimer]
  );

  /**
   * Handle touch end - clear long press timer.
   */
  const handleTouchEnd = useCallback(() => {
    clearLongPressTimer();
  }, [clearLongPressTimer]);

  // Display size only for files
  const sizeDisplay = isFile(item) ? formatBytes(item.size) : '-';

  // Display modified date
  const dateDisplay = formatDate(item.modifiedAt);

  return (
    <div
      className={`file-list-item ${isSelected ? 'file-list-item--selected' : ''}`}
      data-item-id={item.id}
      onClick={handleClick}
      onDoubleClick={handleDoubleClick}
      onContextMenu={handleContextMenu}
      draggable
      onDragStart={handleDragStart}
      onTouchStart={handleTouchStart}
      onTouchMove={handleTouchMove}
      onTouchEnd={handleTouchEnd}
      onTouchCancel={handleTouchEnd}
      role="row"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter') {
          if (isFolder(item)) {
            onNavigate(item.id);
          }
        }
      }}
    >
      <div className="file-list-item-name">
        <span className="file-list-item-icon">{getItemIcon(item)}</span>
        <span className="file-list-item-text">{item.name}</span>
      </div>
      <div className="file-list-item-size">{sizeDisplay}</div>
      <div className="file-list-item-date">{dateDisplay}</div>
    </div>
  );
}
