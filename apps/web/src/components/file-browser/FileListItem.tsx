import {
  useState,
  useCallback,
  useRef,
  type DragEvent,
  type MouseEvent,
  type TouchEvent,
} from 'react';
import type { FolderChild, FilePointer, FolderEntry } from '@cipherbox/crypto';
import { formatDate } from '../../utils/format';
import { isExternalFileDrag } from '../../hooks/useDropUpload';

/**
 * Long press duration in milliseconds for touch context menu.
 */
const LONG_PRESS_DURATION = 500;

/** Drag payload item (id + type). */
export type DragItem = { id: string; type: 'file' | 'folder' };

type FileListItemProps = {
  /** The file or folder item to display */
  item: FolderChild;
  /** Whether this item is currently selected */
  isSelected: boolean;
  /** Parent folder ID (for drag data) */
  parentId: string;
  /** All currently selected item IDs (for multi-select drag) */
  selectedIds: Set<string>;
  /** All items in the current folder (for resolving types of selected IDs) */
  allItems: FolderChild[];
  /** Callback when item is clicked (with modifier key info) */
  onSelect: (
    itemId: string,
    event: { ctrlKey: boolean; shiftKey: boolean; metaKey: boolean }
  ) => void;
  /** Callback when folder is double-clicked to navigate into */
  onNavigate: (folderId: string) => void;
  /** Callback when right-click context menu is requested */
  onContextMenu: (event: MouseEvent, item: FolderChild) => void;
  /** Callback when drag starts */
  onDragStart: (event: DragEvent, item: FolderChild) => void;
  /** Callback when items are dropped onto this folder (folders only) */
  onDrop?: (items: DragItem[], sourceParentId: string) => void;
  /** Callback when external files are dropped onto this folder */
  onExternalFileDrop?: (files: File[], destFolderId: string) => void;
};

/**
 * Type guard for folder entries.
 */
function isFolder(item: FolderChild): item is FolderEntry {
  return item.type === 'folder';
}

/**
 * Type guard for file pointers (v2).
 */
function isFile(item: FolderChild): item is FilePointer {
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
  selectedIds,
  allItems,
  onSelect,
  onNavigate,
  onContextMenu,
  onDragStart,
  onDrop,
  onExternalFileDrop,
}: FileListItemProps) {
  // Ref for long press timer
  const longPressTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const touchStartPosRef = useRef<{ x: number; y: number } | null>(null);

  // Drag-over state for folder drop targets
  const [isDragOver, setIsDragOver] = useState(false);

  /**
   * Handle single click - select the item.
   * Passes modifier key state for multi-selection support.
   */
  const handleClick = useCallback(
    (e: React.MouseEvent) => {
      onSelect(item.id, { ctrlKey: e.ctrlKey, shiftKey: e.shiftKey, metaKey: e.metaKey });
    },
    [item.id, onSelect]
  );

  /**
   * Handle checkbox click - toggle selection without modifiers.
   */
  const handleCheckboxClick = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      // Checkbox click always toggles like Ctrl+click
      onSelect(item.id, { ctrlKey: true, shiftKey: false, metaKey: false });
    },
    [item.id, onSelect]
  );

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
      // Build items array: if dragged item is part of multi-selection, include all selected
      let items: DragItem[];
      if (isSelected && selectedIds.size > 1) {
        items = allItems
          .filter((i) => selectedIds.has(i.id))
          .map((i) => ({ id: i.id, type: i.type }));
      } else {
        items = [{ id: item.id, type: item.type }];
      }

      e.dataTransfer.setData('application/json', JSON.stringify({ items, parentId }));
      e.dataTransfer.effectAllowed = 'move';
      onDragStart(e, item);
    },
    [item, isSelected, selectedIds, allItems, parentId, onDragStart]
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
   * Accepts both internal drags (move) and external file drags (upload).
   */
  const handleDragOver = useCallback(
    (e: DragEvent) => {
      // Only allow drop on folders
      if (!isFolder(item)) return;

      e.preventDefault();
      e.stopPropagation();

      // External files get 'copy' effect, internal moves get 'move'
      e.dataTransfer.dropEffect = isExternalFileDrag(e.dataTransfer) ? 'copy' : 'move';
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
   * Handle drop - move item to this folder, or upload external files.
   */
  const handleDrop = useCallback(
    (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);

      // Only handle drop on folders
      if (!isFolder(item)) return;

      // Read JSON once — empty string means external file drag from OS
      const jsonData = e.dataTransfer.getData('application/json');

      if (!jsonData) {
        // External file drop
        if (e.dataTransfer.files.length > 0 && onExternalFileDrop) {
          const files = Array.from(e.dataTransfer.files);
          onExternalFileDrop(files, item.id);
        }
        return;
      }

      // Internal move operation
      if (!onDrop) return;

      try {
        const parsed = JSON.parse(jsonData) as {
          items: DragItem[];
          parentId: string;
        };

        // Filter out items that are this folder or already in this folder
        const validItems = parsed.items.filter(
          (i) => i.id !== item.id && parsed.parentId !== item.id
        );
        if (validItems.length === 0) return;

        onDrop(validItems, parsed.parentId);
      } catch {
        // Invalid drag data, ignore
      }
    },
    [item, onDrop, onExternalFileDrop]
  );

  // Display size: v2 FilePointers don't have inline size (lives in per-file IPNS metadata).
  // Show '--' for files until size is resolved on download/preview.
  const sizeDisplay = isFile(item) ? '--' : '-';

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
      onDragOver={isFolder(item) && (onDrop || onExternalFileDrop) ? handleDragOver : undefined}
      onDragLeave={isFolder(item) && (onDrop || onExternalFileDrop) ? handleDragLeave : undefined}
      onDrop={isFolder(item) && (onDrop || onExternalFileDrop) ? handleDrop : undefined}
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
      {/* Row 1: Checkbox + Icon + Name (for mobile top row) */}
      <div className="file-list-item-row-top" role="gridcell">
        <span
          className="file-list-item-checkbox"
          onClick={handleCheckboxClick}
          role="checkbox"
          aria-checked={isSelected}
          aria-label={`Select ${item.name}`}
          tabIndex={-1}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              e.stopPropagation();
              onSelect(item.id, { ctrlKey: true, shiftKey: false, metaKey: false });
            }
          }}
        >
          {isSelected ? '[x]' : '[ ]'}
        </span>
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
