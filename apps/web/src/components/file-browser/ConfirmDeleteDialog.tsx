import type { ListingRow } from '../../vault/listing';
import { describeRows } from '../../vault/selection';
import { Modal } from '../ui/Modal';

interface ConfirmDeleteDialogProps {
  /** What the delete will retire; each row becomes a command of its own. */
  rows: ListingRow[];
  onClose: () => void;
  onConfirm: () => void;
  busy: boolean;
  /** The last dispatch's failure, which is why the dialog is still up. */
  error: string | null;
}

export function ConfirmDeleteDialog({
  rows,
  onClose,
  onConfirm,
  busy,
  error,
}: ConfirmDeleteDialogProps) {
  const what = describeRows(rows);
  // A single row is named, so it is quoted; a count is not a name.
  const single = rows.length === 1;
  const target = single ? `"${what}"` : what;
  const inside = rows.some((row) => row.kind === 'folder')
    ? ` and everything inside${single ? ' it' : ''}`
    : '';

  return (
    <Modal onClose={onClose} title={`delete ${what}`} error={error} busy={busy}>
      <div className="dialog-content" data-testid="delete-dialog">
        <p className="dialog-message">{`delete ${target}${inside}?`}</p>
        <div className="dialog-actions">
          <button type="button" className="dialog-button" onClick={onClose} disabled={busy}>
            cancel
          </button>
          <button
            type="button"
            className="dialog-button dialog-button--danger"
            onClick={onConfirm}
            disabled={busy}
            data-testid="delete-confirm"
          >
            {busy ? 'deleting...' : 'delete'}
          </button>
        </div>
      </div>
    </Modal>
  );
}
