import { useState, type FormEvent } from 'react';
import type { ListingRow } from '../../vault/listing';
import { Modal } from '../ui/Modal';

interface RenameDialogProps {
  row: ListingRow;
  onClose: () => void;
  onConfirm: (newName: string) => void;
  busy: boolean;
}

export function RenameDialog({ row, onClose, onConfirm, busy }: RenameDialogProps) {
  const [name, setName] = useState(row.name);
  const trimmed = name.trim();
  const unchanged = trimmed === row.name;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (trimmed !== '' && !unchanged && !busy) onConfirm(trimmed);
  };

  return (
    <Modal open onClose={onClose} title={`rename ${row.name}`}>
      <form className="dialog-content" onSubmit={submit} data-testid="rename-dialog">
        <label className="dialog-label" htmlFor="rename-name">
          new name
        </label>
        <input
          id="rename-name"
          className="dialog-input"
          value={name}
          onChange={(event) => setName(event.target.value)}
          disabled={busy}
          autoComplete="off"
          spellCheck={false}
          autoFocus
        />
        <div className="dialog-actions">
          <button type="button" className="dialog-button" onClick={onClose} disabled={busy}>
            cancel
          </button>
          <button
            type="submit"
            className="dialog-button dialog-button--primary"
            disabled={busy || trimmed === '' || unchanged}
            data-testid="rename-confirm"
          >
            {busy ? 'renaming...' : 'rename'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
