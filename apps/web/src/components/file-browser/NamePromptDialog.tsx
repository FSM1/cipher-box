import { useState, type FormEvent } from 'react';
import { Modal } from '../ui/Modal';

interface NamePromptDialogProps {
  title: string;
  fieldLabel: string;
  /** Seeds the field; a name that trims back to it cannot be submitted. */
  initialName: string;
  confirmLabel: string;
  busyLabel: string;
  /** Prefixes the dialog's test ids and the field's `id`. */
  testId: string;
  busy: boolean;
  /** The last dispatch's failure, which is why the dialog is still up. */
  error: string | null;
  onClose: () => void;
  onConfirm: (name: string) => void;
}

/** Asks for one name — the shape create and rename both need. */
export function NamePromptDialog({
  title,
  fieldLabel,
  initialName,
  confirmLabel,
  busyLabel,
  testId,
  busy,
  error,
  onClose,
  onConfirm,
}: NamePromptDialogProps) {
  const [name, setName] = useState(initialName);
  const trimmed = name.trim();
  const blocked = busy || trimmed === '' || trimmed === initialName.trim();

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!blocked) onConfirm(trimmed);
  };

  return (
    <Modal onClose={onClose} title={title} error={error} busy={busy}>
      <form className="dialog-content" onSubmit={submit} data-testid={`${testId}-dialog`}>
        <label className="dialog-label" htmlFor={`${testId}-name`}>
          {fieldLabel}
        </label>
        <input
          id={`${testId}-name`}
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
            data-testid={`${testId}-cancel`}
          >
            cancel
          </button>
          <button
            type="submit"
            className="dialog-button dialog-button--primary"
            disabled={blocked}
            data-testid={`${testId}-confirm`}
          >
            {busy ? busyLabel : confirmLabel}
          </button>
        </div>
      </form>
    </Modal>
  );
}
