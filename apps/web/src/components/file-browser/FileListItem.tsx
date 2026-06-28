import {
  useState,
  useCallback,
  useRef,
  type DragEvent,
  type MouseEvent,
  type TouchEvent,
} from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import { formatDate, getItemIcon } from '../../utils/format';
import { isExternalFileDrag } from '../../hooks/useDropUpload';

/**
 * Long press duration in milliseconds for touch context menu.
 */
const LONG_PRESS_DURATION = 500;

/** Drag payload item (id + type). */
export type DragItem = { id: string; type: 'file' | 'folder' };

type FileListItemProps = {
  /** The child ref to display (node/v3 SealedChildRef) */
  item: SealedChildRef;
  /** Whether this item is currently selected */
  isSelected: boolean;
  /** Parent folder ID (for drag data) */
  parentId: string;
  /** All currently selected item IDs */
  selectedIds: Set<string>;
  /** All items in the current folder (for multi-select drag) */
  allItems: SealedChildRef[];
  /** Parent folder's decrypted AES-256 key (for resolving file sizes) */
  folderKey: Uint8Array | null;
  /** Callback when item is clicked (with modifier key info) */
  onSelect: (
    itemId: string,
    event: { ctrlKey: boolean; shiftKey: boolean; metaKey: boolean }
  ) => void;
  /** Callback when folder is double-clicked to navigate into */
  onNavigate: (folderId: string) => void;
  /** Callback when right-click context menu is requested */
  onContextMenu: (event: MouseEvent, item: SealedChildRef) => void;
  /** Callback when drag starts */
  onDragStart: (event: DragEvent, item: SealedChildRef) => void;
  /** Callback when items are dropped onto this folder (folders only) */
  onDrop?: (items: DragItem[], sourceParentId: string) => void;
  /** Callback when external files are dropped onto this folder */
  onExternalFileDrop?: (files: File[], destFolderId: string) => void;
};

/**
 * Single row in the file list (node/v3).
 *
 * TODO(phase 63): file/folder discrimination via Node.kind; until then all items display
 * as folders (SealedChildRef has no .type field).
 */
export function FileListItem({
  item,
  isSelected,
  parentId,
  selectedIds,
  allItems,
  folderKey: _folderKey, // TODO(phase 63): used for per-file size resolution
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

  // TODO(phase 63): SealedChildRef has no .type; treat all as folders for navigation
  const isFolder = true; // phase-63 stub

  /**
   * Handle single click - select the item.
   * Uses ipnsName as the stable identifier (SealedChildRef has no .id).
   */
  const handleClick = useCallback(
    (e: React.MouseEvent) => {
      onSelect(item.ipnsName, { ctrlKey: e.ctrlKey, shiftKey: e.shiftKey, metaKey: e.metaKey });
    },
    [item.ipnsName, onSelect]
  );

  /**
   * Handle checkbox click - toggle selection without modifiers.
   */
  const handleCheckboxClick = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      onSelect(item.ipnsName, { ctrlKey: true, shiftKey: false, metaKey: false });
    },
    [item.ipnsName, onSelect]
  );

  /**
   * Handle double click - navigate into folder.
   * TODO(phase 63): check Node.kind before navigating; stub navigates all items.
   */
  const handleDoubleClick = useCallback(() => {
    // phase-63 stub: navigate as if all items are folders
    onNavigate(item.ipnsName);
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
   * Handle mobile action button click.
   */
  const handleActionButtonClick = useCallback(
    (e: React.MouseEvent<HTMLButtonElement>) => {
      e.stopPropagation();
      const rect = e.currentTarget.getBoundingClientRect();
      const syntheticEvent = {
        preventDefault: () => {},
        stopPropagation: () => {},
        clientX: rect.left,
        clientY: rect.bottom,
      } as unknown as MouseEvent;
      onContextMenu(syntheticEvent, item);
    },
    [item, onContextMenu]
  );

  /**
   * Handle drag start - serialize item data.
   * TODO(phase 63): SealedChildRef has no .type or .id; use ipnsName and stub type.
   */
  const handleDragStart = useCallback(
    (e: DragEvent) => {
      let items: DragItem[];
      if (isSelected && selectedIds.size > 1) {
        items = allItems
          .filter((i) => selectedIds.has(i.ipnsName))
          .map((i) => ({ id: i.ipnsName, type: 'folder' as const })); // TODO(phase 63) stub type
      } else {
        items = [{ id: item.ipnsName, type: 'folder' as const }]; // TODO(phase 63) stub type
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

      touchStartPosRef.current = { x: touch.clientX, y: touch.clientY };

      longPressTimerRef.current = setTimeout(() => {
        const syntheticEvent = {
          preventDefault: () => {},
          stopPropagation: () => {},
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
   * Handle drag over - allow drop on folder items.
   */
  const handleDragOver = useCallback(
    (e: DragEvent) => {
      if (!isFolder) return;

      e.preventDefault();
      e.stopPropagation();

      e.dataTransfer.dropEffect = isExternalFileDrag(e.dataTransfer) ? 'copy' : 'move';
      setIsDragOver(true);
    },
    [isFolder]
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
   * TODO(phase 63): uses ipnsName as folder destination identifier.
   */
  const handleDrop = useCallback(
    (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);

      if (!isFolder) return;

      const jsonData = e.dataTransfer.getData('application/json');

      if (!jsonData) {
        if (e.dataTransfer.files.length > 0 && onExternalFileDrop) {
          const files = Array.from(e.dataTransfer.files);
          onExternalFileDrop(files, item.ipnsName); // TODO(phase 63): ipnsName as id
        }
        return;
      }

      if (!onDrop) return;

      try {
        const parsed = JSON.parse(jsonData) as {
          items: DragItem[];
          parentId: string;
        };

        const validItems = parsed.items.filter(
          (i) => i.id !== item.ipnsName && parsed.parentId !== item.ipnsName
        );
        if (validItems.length === 0) return;

        onDrop(validItems, parsed.parentId);
      } catch {
        // Invalid drag data, ignore
      }
    },
    [item, onDrop, onExternalFileDrop, isFolder]
  );

  // TODO(phase 63): SealedChildRef has no .type; display all items with folder icon as placeholder
  const itemType = 'folder'; // phase-63 stub

  // Display size: stub until read-chain provides NodeContent.size
  // TODO(phase 63): resolve size via Node read-chain
  const sizeDisplay = '-';

  // Display modified date: SealedChildRef has no modifiedAt
  // TODO(phase 63): resolve modifiedAt from Node envelope
  const dateDisplay = formatDate(0); // phase-63 stub

  const className = [
    'file-list-item',
    isSelected ? 'file-list-item--selected' : '',
    isDragOver && isFolder ? 'file-list-item--drag-over' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div
      className={className}
      data-item-id={item.ipnsName}
      onClick={handleClick}
      onDoubleClick={handleDoubleClick}
      onContextMenu={handleContextMenu}
      draggable
      onDragStart={handleDragStart}
      onDragOver={isFolder && (onDrop || onExternalFileDrop) ? handleDragOver : undefined}
      onDragLeave={isFolder && (onDrop || onExternalFileDrop) ? handleDragLeave : undefined}
      onDrop={isFolder && (onDrop || onExternalFileDrop) ? handleDrop : undefined}
      onTouchStart={handleTouchStart}
      onTouchMove={handleTouchMove}
      onTouchEnd={handleTouchEnd}
      onTouchCancel={handleTouchEnd}
      role="row"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter') {
          if (isFolder) {
            onNavigate(item.ipnsName);
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
              onSelect(item.ipnsName, { ctrlKey: true, shiftKey: false, metaKey: false });
            }
          }}
        >
          {isSelected ? '[x]' : '[ ]'}
        </span>
        <span className="file-list-item-icon" aria-hidden="true">
          {getItemIcon(itemType)}
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

      {/* Mobile action button - hidden on desktop via CSS */}
      <div className="file-list-item-mobile-actions" role="gridcell">
        <button
          type="button"
          className="file-list-item-action-btn"
          onClick={handleActionButtonClick}
          aria-label={`Actions for ${item.name}`}
        >
          ...
        </button>
      </div>
    </div>
  );
}
