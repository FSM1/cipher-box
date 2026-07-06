/**
 * SharedFolderRow -- Row component for items within a shared folder.
 *
 * Shows [RW] or [RO] badge based on the share's permission level.
 * Supports inline renaming when isRenaming is true.
 * Supports multi-select (Ctrl/Cmd+click) and drag-and-drop move onto folder rows.
 */

import type React from 'react';
import { useState, useCallback } from 'react';
import type { MouseEvent, DragEvent, KeyboardEvent } from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import type { ResolvedChild } from '@cipherbox/sdk';
import { isExternalFileDrag } from '../../hooks/useDropUpload';
import { isFileRef } from '../../utils/fileTypes';
import { formatBytes, formatDate } from '../../utils/format';
import type { DragItem } from './FileListItem';

type DragPayload = {
  items: DragItem[];
};

export type SharedFolderRowProps = {
  item: SealedChildRef;
  /**
   * Resolved display projection of `item` (68.2-08, D-02) -- when present,
   * `kind`/`size`/`modifiedAt` render from this instead of `item`'s own
   * (legacy, unreliable) display-mirror fields. `item` itself stays the
   * identity/crypto carrier for callbacks (drag payload id, rename/delete/
   * move calls), matching `FileListItem.tsx`'s owned-folder dual-prop
   * pattern (Plan 06). `undefined` while the resolved listing is still
   * loading -- falls back to `item`'s own fields (may render the em-dash
   * placeholder / kind-cache default in that window).
   */
  resolved?: ResolvedChild;
  permission: 'read' | 'write' | null;
  isRenaming: boolean;
  renameValue: string;
  renameInputRef: React.RefObject<HTMLInputElement>;
  onRenameChange: (value: string) => void;
  onRenameKeyDown: (e: React.KeyboardEvent) => void;
  onRenameSubmit: () => void;
  onContextMenu: (e: MouseEvent) => void;
  onDoubleClick: () => void;
  /** Whether this row is currently selected */
  isSelected?: boolean;
  /** Click handler for multi-select (receives modifier key info) */
  onSelect?: (e: { ctrlKey: boolean; shiftKey: boolean; metaKey: boolean }) => void;
  /**
   * Callback invoked when an internal drag is dropped onto this folder row.
   * Receives destination folder ID + IPNS name and the dragged source items, so
   * the parent moves exactly what was dragged rather than re-deriving from the
   * current selection. Only set on folder items.
   */
  onMoveItemTo?: (destFolderId: string, destIpnsName: string, draggedItems: DragItem[]) => void;
  /** Currently selected items (for multi-select-aware drag payload) */
  selectedItems?: SealedChildRef[];
};

export function SharedFolderRow({
  item,
  resolved,
  permission,
  isRenaming,
  renameValue,
  renameInputRef,
  onRenameChange,
  onRenameKeyDown,
  onRenameSubmit,
  onContextMenu,
  onDoubleClick,
  isSelected = false,
  onSelect,
  onMoveItemTo,
  selectedItems = [],
}: SharedFolderRowProps) {
  // 68.2-08 (D-02): prefer the resolved listing's kind when available --
  // isFileRef reads `.kind` directly off a ResolvedChild, no kind-cache
  // lookup needed. Falls back to the legacy kind-cache-backed SealedChildRef
  // path while the resolved listing is still loading.
  const isFolder = !isFileRef(resolved ?? item);
  const icon = isFolder ? '📁' : '📄';
  // 68.2-08 (D-02): size/modifiedAt render from the resolved listing when
  // available -- em dash while still loading (SealedChildRef's own display
  // mirrors are the pre-68.2-08 fallback, kept for the loading window only).
  const size =
    typeof resolved?.size === 'number' && Number.isFinite(resolved.size)
      ? formatBytes(resolved.size)
      : '—';
  const date =
    typeof resolved?.modifiedAt === 'number' && Number.isFinite(resolved.modifiedAt)
      ? formatDate(resolved.modifiedAt)
      : '—';
  const isWrite = permission === 'write';

  // Internal drag-over visual state
  const [isDragOver, setIsDragOver] = useState(false);

  // ---------------------------------------------------------------------------
  // Drag source -- multi-select-aware (mirrors FileListItem :160-177)
  // ---------------------------------------------------------------------------
  const handleDragStart = useCallback(
    (e: DragEvent) => {
      // If this item is part of a multi-select, payload includes all selected items.
      // D-02: per-item kind read (SealedChildRef has no .id/.type; ipnsName is the
      // stable identifier, and isFileRef reads the kind cache per item).
      const dragItems: DragItem[] =
        isSelected && selectedItems.length > 1
          ? selectedItems.map((i) => ({
              id: i.ipnsName,
              type: isFileRef(i) ? ('file' as const) : ('folder' as const),
            }))
          : [
              {
                id: item.ipnsName,
                type: isFileRef(item) ? ('file' as const) : ('folder' as const),
              },
            ];

      const payload: DragPayload = { items: dragItems };
      e.dataTransfer.setData('application/json', JSON.stringify(payload));
      e.dataTransfer.effectAllowed = 'move';
    },
    [item, isSelected, selectedItems]
  );

  // ---------------------------------------------------------------------------
  // Drop target -- folder rows only (mirrors FileListItem :275-317)
  // ---------------------------------------------------------------------------
  const handleDragOver = useCallback(
    (e: DragEvent) => {
      if (!isFolder || !onMoveItemTo) return;
      e.preventDefault();
      e.stopPropagation();

      // Distinguish internal moves from external file uploads
      e.dataTransfer.dropEffect = isExternalFileDrag(e.dataTransfer) ? 'copy' : 'move';
      setIsDragOver(true);
    },
    [isFolder, onMoveItemTo]
  );

  const handleDragLeave = useCallback(
    (e: DragEvent) => {
      if (!isFolder || !onMoveItemTo) return;
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);
    },
    [isFolder, onMoveItemTo]
  );

  const handleDrop = useCallback(
    (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);

      // Only handle drops on folder rows
      if (!isFolder || !onMoveItemTo) return;

      // Distinguish internal move from external file upload
      const jsonData = e.dataTransfer.getData('application/json');

      if (!jsonData) {
        // External file drop — no handler here; the parent SharedFileBrowser
        // handles external drops at the container level
        return;
      }

      // Internal move — parse defensively (T-49-13)
      let parsed: DragPayload;
      try {
        parsed = JSON.parse(jsonData) as DragPayload;
        if (!Array.isArray(parsed.items) || parsed.items.length === 0) return;
      } catch {
        // Invalid JSON — treat as external and let parent handle it
        return;
      }

      // Guard: never drop a folder onto itself (one of the dragged items) — that
      // would move it into itself and cycle the tree (mirrors FileListItem).
      // TODO(phase 63): SealedChildRef uses ipnsName as identifier
      if (parsed.items.some((i) => i.id === item.ipnsName)) return;

      // Route through the parent's handleDropOnFolder-equivalent, forwarding the
      // dragged items so the parent moves exactly what was dragged. Per-item
      // validation (name collision + write-capability) is in the SDK.
      onMoveItemTo(item.ipnsName, item.ipnsName, parsed.items);
    },
    [isFolder, item, onMoveItemTo]
  );

  // ---------------------------------------------------------------------------
  // Click handler for selection
  // ---------------------------------------------------------------------------
  const handleClick = useCallback(
    (e: MouseEvent) => {
      if (isRenaming) return;
      if (onSelect) {
        onSelect({ ctrlKey: e.ctrlKey, shiftKey: e.shiftKey, metaKey: e.metaKey });
      }
    },
    [isRenaming, onSelect]
  );

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (isRenaming) return;
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        // Ctrl/Cmd + Enter/Space toggles (multi-)selection for keyboard parity
        // with Ctrl/Cmd+click; plain Enter/Space navigates.
        if ((e.ctrlKey || e.metaKey) && onSelect) {
          onSelect({ ctrlKey: e.ctrlKey, shiftKey: e.shiftKey, metaKey: e.metaKey });
        } else {
          onDoubleClick();
        }
      }
    },
    [isRenaming, onDoubleClick, onSelect]
  );

  const className = [
    'file-list-row',
    isSelected ? 'file-list-row--selected' : '',
    isDragOver && isFolder ? 'file-list-item--drag-over' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div
      className={className}
      role="row"
      tabIndex={0}
      draggable
      onDragStart={handleDragStart}
      onDragOver={isFolder && onMoveItemTo ? handleDragOver : undefined}
      onDragLeave={isFolder && onMoveItemTo ? handleDragLeave : undefined}
      onDrop={isFolder && onMoveItemTo ? handleDrop : undefined}
      onClick={handleClick}
      onDoubleClick={isRenaming ? undefined : onDoubleClick}
      onContextMenu={(e) => {
        e.preventDefault();
        onContextMenu(e);
      }}
      onKeyDown={handleKeyDown}
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
        {size}
      </div>
      <div className="file-list-cell file-list-cell-date" role="gridcell">
        {date}
      </div>
    </div>
  );
}
