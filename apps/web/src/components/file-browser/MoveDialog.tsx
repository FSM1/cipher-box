import { useFolderPicker } from '../../hooks/useFolderPicker';
import type { ListingRow } from '../../vault/listing';
import { Modal } from '../ui/Modal';

interface MoveDialogProps {
  row: ListingRow;
  /** The folder the row is in today; moving into it would be a no-op. */
  parent: Uint8Array | null;
  onClose: () => void;
  onConfirm: (newParent: Uint8Array) => void;
  busy: boolean;
}

/** Picks a destination by walking the vault one folder at a time. */
export function MoveDialog({ row, parent, onClose, onConfirm, busy }: MoveDialogProps) {
  const picker = useFolderPicker(parent, row.key);
  const here = picker.trail[picker.trail.length - 1];
  const destination = picker.destination;
  const canMove = !busy && destination !== null && !picker.atHome;

  return (
    <Modal open onClose={onClose} title={`move ${row.name}`}>
      <div className="dialog-content" data-testid="move-dialog">
        <p className="dialog-label">
          {'destination: '}
          <span className="move-dialog-destination" data-testid="move-dialog-destination">
            {here === undefined ? '...' : here.name || '/'}
          </span>
        </p>
        <div className="move-dialog-list" role="listbox" aria-label="destination folder">
          {!picker.isRoot && (
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
