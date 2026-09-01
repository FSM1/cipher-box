import { useFolderPicker } from '../../hooks/useFolderPicker';
import { NO_KEYS } from '../../vault/selection';
import { FolderPickerBody } from '../ui/FolderPickerBody';
import { Modal } from '../ui/Modal';

interface RestoreIntoDialogProps {
  /** The bin entry the restore puts back. */
  name: string;
  onClose: () => void;
  onConfirm: (into: Uint8Array) => void;
  busy: boolean;
  /** The last dispatch's failure, which is why the dialog is still up. */
  error: string | null;
}

/**
 * Picks another destination for a restore the engine refused, by walking the
 * vault from its root one folder at a time.
 */
export function RestoreIntoDialog({
  name,
  onClose,
  onConfirm,
  busy,
  error,
}: RestoreIntoDialogProps) {
  // A binned node is out of the tree, so no listing can offer its own subtree.
  const picker = useFolderPicker(null, NO_KEYS);
  const destination = picker.destination;

  return (
    <Modal onClose={onClose} title={`restore ${name}`} error={error} busy={busy}>
      <div className="dialog-content" data-testid="restore-dialog">
        <FolderPickerBody picker={picker} />
        <div className="dialog-actions">
          <button type="button" className="dialog-button" onClick={onClose} disabled={busy}>
            cancel
          </button>
          <button
            type="button"
            className="dialog-button dialog-button--primary"
            onClick={() => destination !== null && onConfirm(destination)}
            disabled={busy || destination === null}
            data-testid="restore-confirm"
          >
            {busy ? 'restoring...' : 'restore here'}
          </button>
        </div>
      </div>
    </Modal>
  );
}
