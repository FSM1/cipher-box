import type { ListingRow } from '../../vault/listing';
import { Modal } from '../ui/Modal';

interface ConfirmDeleteDialogProps {
  row: ListingRow;
  onClose: () => void;
  onConfirm: () => void;
  busy: boolean;
  /** The last dispatch's failure, which is why the dialog is still up. */
  error: string | null;
}

export function ConfirmDeleteDialog({
  row,
  onClose,
  onConfirm,
  busy,
  error,
}: ConfirmDeleteDialogProps) {
  return (
    <Modal onClose={onClose} title={`delete ${row.name}`} error={error} busy={busy}>
      <div className="dialog-content" data-testid="delete-dialog">
        <p className="dialog-message">
          {row.kind === 'folder'
            ? `delete "${row.name}" and everything inside it?`
            : `delete "${row.name}"?`}
        </p>
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
