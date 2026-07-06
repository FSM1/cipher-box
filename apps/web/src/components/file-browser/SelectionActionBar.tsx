import { useMemo } from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import type { ResolvedChild } from '@cipherbox/sdk';
import { isFileRefResolved } from '../../utils/fileTypes';

type SelectionActionBarProps = {
  /** Selected items (identity-only raw refs -- no `.kind`) */
  selectedItems: SealedChildRef[];
  /**
   * SDK-resolved listing for the current folder (68.2-15). Supplies the
   * per-child `kind` (keyed by ipnsName) that the raw `selectedItems` lack
   * after the 68.2-11 kind-cache removal -- drives the file/folder count copy
   * and the download-button affordance.
   */
  resolvedChildren: ResolvedChild[];
  /** Whether an operation is in progress */
  isLoading: boolean;
  /** Callback to clear selection */
  onClearSelection: () => void;
  /** Callback to download selected files. Omit to hide the download button. */
  onDownload?: () => void;
  /** Callback to move selected items */
  onMove: () => void;
  /** Callback to delete selected items. Omit to hide the delete button. */
  onDelete?: () => void;
};

/**
 * Action bar shown when multiple items are selected.
 * Displays selection count and batch action buttons.
 */
export function SelectionActionBar({
  selectedItems,
  resolvedChildren,
  isLoading,
  onClearSelection,
  onDownload,
  onMove,
  onDelete,
}: SelectionActionBarProps) {
  // Kind-aware count copy (D-02) — pre-v2.0 contract asserted by
  // full-workflow.spec.ts 4.6: "2 files selected" / "2 files, 1 folder selected".
  // 68.2-15: raw `selectedItems` carry no `.kind`; classify against the
  // SDK-resolved listing keyed by ipnsName.
  const resolvedByIpnsName = useMemo(
    () => new Map(resolvedChildren.map((r) => [r.ipnsName, r])),
    [resolvedChildren]
  );
  const fileCount = selectedItems.filter((it) => isFileRefResolved(it, resolvedByIpnsName)).length;
  const folderCount = selectedItems.length - fileCount;
  const parts: string[] = [];
  if (fileCount > 0) parts.push(fileCount === 1 ? '1 file' : `${fileCount} files`);
  if (folderCount > 0) parts.push(folderCount === 1 ? '1 folder' : `${folderCount} folders`);
  const description = parts.join(', ') || '0 items';
  // Download only makes sense when at least one selected item is a file (D-02 kind cache).
  const hasFileSelected = fileCount > 0;

  return (
    <div className="selection-action-bar" role="toolbar" aria-label="Selection actions">
      <div className="selection-action-bar-info">
        <span className="selection-action-bar-count">{description} selected</span>
        <button
          type="button"
          className="selection-action-bar-clear"
          onClick={onClearSelection}
          aria-label="Clear selection"
        >
          [clear]
        </button>
      </div>
      <div className="selection-action-bar-actions">
        {onDownload && hasFileSelected && (
          <button
            type="button"
            className="toolbar-btn toolbar-btn--secondary"
            onClick={onDownload}
            disabled={isLoading}
            aria-label={`Download ${description}`}
          >
            &#8595; download
          </button>
        )}
        <button
          type="button"
          className="toolbar-btn toolbar-btn--secondary"
          onClick={onMove}
          disabled={isLoading}
          aria-label={`Move ${description}`}
        >
          &#8594; move
        </button>
        {onDelete && (
          <button
            type="button"
            className="toolbar-btn toolbar-btn--secondary selection-action-bar-delete"
            onClick={onDelete}
            disabled={isLoading}
            aria-label={`Delete ${description}`}
          >
            &#128465; delete
          </button>
        )}
      </div>
    </div>
  );
}
