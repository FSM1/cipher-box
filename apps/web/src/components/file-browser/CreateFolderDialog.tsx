import { useState, type FormEvent } from 'react';
import { Modal } from '../ui/Modal';

interface CreateFolderDialogProps {
  onClose: () => void;
  onConfirm: (name: string) => void;
  busy: boolean;
}

export function CreateFolderDialog({ onClose, onConfirm, busy }: CreateFolderDialogProps) {
  const [name, setName] = useState('');
  const trimmed = name.trim();

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (trimmed !== '' && !busy) onConfirm(trimmed);
  };

  return (
    <Modal open onClose={onClose} title="new folder">
      <form className="dialog-content" onSubmit={submit} data-testid="create-folder-dialog">
        <label className="dialog-label" htmlFor="create-folder-name">
          folder name
        </label>
        <input
          id="create-folder-name"
          className="dialog-input"
          value={name}
          onChange={(event) => setName(event.target.value)}
          disabled={busy}
          autoComplete="off"
          spellCheck={false}
          autoFocus
        />
        <div className="dialog-actions">
          <button
            type="button"
            className="dialog-button"
            onClick={onClose}
            disabled={busy}
            data-testid="create-folder-cancel"
          >
            cancel
          </button>
          <button
            type="submit"
            className="dialog-button dialog-button--primary"
            disabled={busy || trimmed === ''}
            data-testid="create-folder-confirm"
          >
            {busy ? 'creating...' : 'create'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
