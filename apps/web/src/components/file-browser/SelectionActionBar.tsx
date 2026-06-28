import type { SealedChildRef } from '@cipherbox/core';

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
  onDownload: _onDownload, // TODO(phase 63): deferred until Node.kind discrimination
  onMove,
  onDelete,
}: SelectionActionBarProps) {
  // TODO(phase 63): SealedChildRef has no .type; kind discrimination deferred to Node.kind
  // phase-63 stub: treat all selected as folders, no file-specific actions
  const folderCount = selectedItems.length;
  const description = folderCount === 1 ? '1 item' : `${folderCount} items`;

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
        {/* TODO(phase 63): download button deferred until Node.kind discrimination available */}
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
