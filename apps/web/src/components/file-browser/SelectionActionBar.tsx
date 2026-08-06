import type { ListingRow } from '../../vault/listing';
import { describeRows } from '../../vault/selection';

interface SelectionActionBarProps {
  /** The selected rows; the bar renders nothing for an empty selection. */
  rows: ListingRow[];
  /** True while a command is in flight, which disables every action. */
  busy: boolean;
  onClear: () => void;
  onDownload: () => void;
  onMove: () => void;
  onDelete: () => void;
}

/** The batch commands, over whatever the listing has selected. */
export function SelectionActionBar({
  rows,
  busy,
  onClear,
  onDownload,
  onMove,
  onDelete,
}: SelectionActionBarProps) {
  if (rows.length === 0) return null;
  const files = rows.filter((row) => row.kind === 'file').length;

  return (
    <div
      className="selection-action-bar"
      role="toolbar"
      aria-label="selection actions"
      data-testid="selection-action-bar"
    >
      <span className="selection-action-bar-count" data-testid="selection-count">
        {`${describeRows(rows)} selected`}
      </span>
      <div className="selection-action-bar-actions">
        {files > 0 && (
          <button
            type="button"
            className="file-browser-toolbar-button"
            onClick={onDownload}
            disabled={busy}
            data-testid="selection-download"
          >
            [DOWNLOAD]
          </button>
        )}
        <button
          type="button"
          className="file-browser-toolbar-button"
          onClick={onMove}
          disabled={busy}
          data-testid="selection-move"
        >
          [MOVE]
        </button>
        <button
          type="button"
          className="file-browser-toolbar-button selection-action-bar-delete"
          onClick={onDelete}
          disabled={busy}
          data-testid="selection-delete"
        >
          [DELETE]
        </button>
        <button
          type="button"
          className="selection-action-bar-clear"
          onClick={onClear}
          disabled={busy}
          data-testid="selection-clear"
        >
          [clear]
        </button>
      </div>
    </div>
  );
}
