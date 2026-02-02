import {
  useState,
  useCallback,
  useRef,
  type DragEvent,
  type MouseEvent,
  type TouchEvent,
} from 'react';
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
  /** Callback when an item is dropped onto this folder (folders only) */
  onDrop?: (sourceId: string, sourceType: 'file' | 'folder', sourceParentId: string) => void;
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
 * Get text prefix for item type (terminal-style).
 */
function getItemIcon(item: FolderChild): string {
  if (isFolder(item)) {
    return '[DIR]';
  }
  return '[FILE]';
}

/* File extension helper removed - TYPE column no longer used */

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
  onDrop,
}: FileListItemProps) {
  // Ref for long press timer
  const longPressTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const touchStartPosRef = useRef<{ x: number; y: number } | null>(null);

  // Drag-over state for folder drop targets
  const [isDragOver, setIsDragOver] = useState(false);

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

  /**
   * Handle drag over - allow drop on folders.
   */
  const handleDragOver = useCallback(
    (e: DragEvent) => {
      // Only allow drop on folders
      if (!isFolder(item)) return;

      e.preventDefault();
      e.stopPropagation();
      e.dataTransfer.dropEffect = 'move';
      setIsDragOver(true);
    },
    [item]
  );

  /**
   * Handle drag leave - clear drag-over state.
   */
  const handleDragLeave = useCallback((e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  /**
   * Handle drop - move item to this folder.
   */
  const handleDrop = useCallback(
    (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);

      // Only handle drop on folders
      if (!isFolder(item) || !onDrop) return;

      try {
        const data = e.dataTransfer.getData('application/json');
        if (!data) return;

        const parsed = JSON.parse(data) as {
          id: string;
          type: 'file' | 'folder';
          parentId: string;
        };

        // Don't allow dropping onto self
        if (parsed.id === item.id) return;

        // Don't allow dropping if already in this folder
        if (parsed.parentId === item.id) return;

        onDrop(parsed.id, parsed.type, parsed.parentId);
      } catch {
        // Invalid drag data, ignore
      }
    },
    [item, onDrop]
  );

  // Display size only for files (folders show "-")
  const sizeDisplay = isFile(item) ? formatBytes(item.size) : '-';

  // Display modified date
  const dateDisplay = formatDate(item.modifiedAt);

  // Build class name with drag-over state
  const className = [
    'file-list-item',
    isSelected ? 'file-list-item--selected' : '',
    isDragOver && isFolder(item) ? 'file-list-item--drag-over' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div
      className={className}
      data-item-id={item.id}
      onClick={handleClick}
      onDoubleClick={handleDoubleClick}
      onContextMenu={handleContextMenu}
      draggable
      onDragStart={handleDragStart}
      onDragOver={isFolder(item) && onDrop ? handleDragOver : undefined}
      onDragLeave={isFolder(item) && onDrop ? handleDragLeave : undefined}
      onDrop={isFolder(item) && onDrop ? handleDrop : undefined}
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
      {/* Row 1: Icon + Name (for mobile top row) */}
      <div className="file-list-item-row-top" role="gridcell">
        <span className="file-list-item-icon" aria-hidden="true">
          {getItemIcon(item)}
        </span>
        <span className="file-list-item-name">{item.name}</span>
      </div>

      {/* Row 2: Size + Date (for mobile bottom row) */}
      <div className="file-list-item-row-bottom">
        <span className="file-list-item-size" role="gridcell">
          {sizeDisplay}
        </span>
        <span className="file-list-item-date" role="gridcell">
          {dateDisplay}
        </span>
      </div>
    </div>
  );
}
