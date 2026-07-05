import type { SealedChildRef } from '@cipherbox/core';
import { isFileRef } from '../../utils/fileTypes';

type SelectionActionBarProps = {
  /** Selected items */
  selectedItems: SealedChildRef[];
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
  isLoading,
  onClearSelection,
  onDownload,
  onMove,
  onDelete,
}: SelectionActionBarProps) {
  // Kind-aware count copy (D-02 kind cache) — pre-v2.0 contract asserted by
  // full-workflow.spec.ts 4.6: "2 files selected" / "2 files, 1 folder selected".
  const fileCount = selectedItems.filter(isFileRef).length;
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
