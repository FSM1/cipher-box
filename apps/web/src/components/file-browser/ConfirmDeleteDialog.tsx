import type { ListingRow } from '../../vault/listing';
import { Modal } from '../ui/Modal';

interface ConfirmDeleteDialogProps {
  row: ListingRow;
  onClose: () => void;
  onConfirm: () => void;
  busy: boolean;
}

/** Deleting a folder takes everything under it, so the prompt says so. */
export function ConfirmDeleteDialog({ row, onClose, onConfirm, busy }: ConfirmDeleteDialogProps) {
  return (
    <Modal open onClose={onClose} title={`delete ${row.name}`}>
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
