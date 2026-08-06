import { useMemo } from 'react';
import { useFolderPicker } from '../../hooks/useFolderPicker';
import type { ListingRow } from '../../vault/listing';
import { describeRows } from '../../vault/selection';
import { Modal } from '../ui/Modal';

interface MoveDialogProps {
  /** What the move will relink; each row becomes a command of its own. */
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
        <p className="dialog-label">
          {'destination: '}
          <span className="move-dialog-destination" data-testid="move-dialog-destination">
            {picker.destinationName === null ? '...' : picker.destinationName || '/'}
          </span>
        </p>
        <div className="move-dialog-list" role="group" aria-label="destination folder">
          {picker.canLeave && (
            <button
              type="button"
              className="move-dialog-entry"
              onClick={picker.leave}
              data-testid="move-dialog-up"
            >
              [..]
            </button>
          )}
          {picker.isLoading && <p className="move-dialog-empty">{'// loading...'}</p>}
          {picker.error !== null && (
            <p className="move-dialog-empty" role="alert">
              {picker.error}
            </p>
          )}
          {!picker.isLoading && picker.folders.length === 0 && picker.error === null && (
            <p className="move-dialog-empty">{'// no subfolders'}</p>
          )}
          {picker.folders.map((folder) => (
            <button
              key={folder.key}
              type="button"
              className="move-dialog-entry"
              onClick={() => picker.enter(folder.id)}
              data-testid="move-dialog-folder"
            >
              <span aria-hidden="true">[DIR]</span> {folder.name}
            </button>
          ))}
        </div>
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
