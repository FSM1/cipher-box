import type { FolderChild } from '@cipherbox/crypto';

type SelectionActionBarProps = {
  /** Selected items */
  selectedItems: FolderChild[];
  /** Whether an operation is in progress */
  isLoading: boolean;
  /** Callback to clear selection */
  onClearSelection: () => void;
  /** Callback to download selected files */
  onDownload: () => void;
  /** Callback to move selected items */
  onMove: () => void;
  /** Callback to delete selected items */
  onDelete: () => void;
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
  const fileCount = selectedItems.filter((i) => i.type === 'file').length;
  const folderCount = selectedItems.filter((i) => i.type === 'folder').length;

  // Build description like "3 files", "2 folders", or "2 files, 1 folder"
  const parts: string[] = [];
  if (fileCount > 0) parts.push(`${fileCount} file${fileCount !== 1 ? 's' : ''}`);
  if (folderCount > 0) parts.push(`${folderCount} folder${folderCount !== 1 ? 's' : ''}`);
  const description = parts.join(', ');

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
        {fileCount > 0 && (
          <button
            type="button"
            className="toolbar-btn toolbar-btn--secondary"
            onClick={onDownload}
            disabled={isLoading}
            aria-label={`Download ${fileCount} file${fileCount !== 1 ? 's' : ''}`}
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
        <button
          type="button"
          className="toolbar-btn toolbar-btn--secondary selection-action-bar-delete"
          onClick={onDelete}
          disabled={isLoading}
          aria-label={`Delete ${description}`}
        >
          &#128465; delete
        </button>
      </div>
    </div>
  );
}
