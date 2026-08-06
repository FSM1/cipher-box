import type { ListingRow } from '../../vault/listing';
import { describeRows } from '../../vault/selection';
import { Modal } from '../ui/Modal';

interface ConfirmDeleteDialogProps {
  /** The rows the delete will retire, named as one or counted as many. */
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
  const recursive = rows.some((row) => row.kind === 'folder');
  const message =
    rows.length === 1
      ? `delete "${what}"${recursive ? ' and everything inside it' : ''}?`
      : `delete ${what}${recursive ? ' and everything inside' : ''}?`;

  return (
    <Modal onClose={onClose} title={`delete ${what}`} error={error} busy={busy}>
      <div className="dialog-content" data-testid="delete-dialog">
        <p className="dialog-message">{message}</p>
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
