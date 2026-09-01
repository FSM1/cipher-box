import { useMemo } from 'react';
import { useFolderPicker } from '../../hooks/useFolderPicker';
import type { ListingRow } from '../../vault/listing';
import { describeRows } from '../../vault/selection';
import { FolderPickerBody } from '../ui/FolderPickerBody';
import { Modal } from '../ui/Modal';

interface MoveDialogProps {
  /** The rows the move will relink, named as one or counted as many. */
  rows: ListingRow[];
  /** The folder the rows are in today; moving into it would be a no-op. */
  parent: Uint8Array | null;
  onClose: () => void;
  onConfirm: (newParent: Uint8Array) => void;
  busy: boolean;
  /** The last dispatch's failure, which is why the dialog is still up. */
  error: string | null;
}

/** Picks a destination by walking the vault one folder at a time. */
export function MoveDialog({ rows, parent, onClose, onConfirm, busy, error }: MoveDialogProps) {
  const excluded = useMemo(() => new Set(rows.map((row) => row.key)), [rows]);
  const picker = useFolderPicker(parent, excluded);
  const destination = picker.destination;
  const canMove = !busy && destination !== null && !picker.atHome;

  return (
    <Modal onClose={onClose} title={`move ${describeRows(rows)}`} error={error} busy={busy}>
      <div className="dialog-content" data-testid="move-dialog">
        <FolderPickerBody picker={picker} />
        <div className="dialog-actions">
          <button type="button" className="dialog-button" onClick={onClose} disabled={busy}>
            cancel
          </button>
          <button
            type="button"
            className="dialog-button dialog-button--primary"
            onClick={() => destination !== null && onConfirm(destination)}
            disabled={!canMove}
            data-testid="move-confirm"
          >
            {busy ? 'moving...' : 'move here'}
          </button>
        </div>
      </div>
    </Modal>
  );
}
