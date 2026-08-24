import { useState, type FormEvent } from 'react';
import { parseContactCode } from '../../sharing/contactCode';
import { Modal } from '../ui/Modal';

interface ImportContactDialogProps {
  busy: boolean;
  /**
   * The engine's refusal, rendered as it worded it: a rejected binding is a
   * trust verdict, and a generic "import failed" would hide which one it was.
   */
  error: string | null;
  onClose: () => void;
  onConfirm: (contactCode: Uint8Array) => void;
}

/**
 * Takes a contact code by paste and hands its bytes to the engine. Identity
 * keys arrive only out-of-band (blueprint/api.md "Contact exchange"), and the
 * code authenticates itself — nothing here reads inside it.
 */
export function ImportContactDialog({ busy, error, onClose, onConfirm }: ImportContactDialogProps) {
  const [pasted, setPasted] = useState('');
  const code = parseContactCode(pasted);
  const unreadable = pasted.trim() !== '' && code === null;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!busy && code !== null) onConfirm(code);
  };

  return (
    <Modal onClose={onClose} title="import contact" error={error} busy={busy}>
      <form className="dialog-content" onSubmit={submit} data-testid="import-contact-dialog">
        <label className="dialog-label" htmlFor="import-contact-code">
          contact code
        </label>
        <textarea
          id="import-contact-code"
          className="dialog-input sharing-code-field"
          value={pasted}
          onChange={(event) => setPasted(event.target.value)}
          disabled={busy}
          autoComplete="off"
          spellCheck={false}
          autoFocus
        />
        {unreadable && (
          <p className="sharing-hint" data-testid="import-contact-unreadable">
            {'// that is not a contact code — paste it exactly as it was sent'}
          </p>
        )}
        <div className="dialog-actions">
          <button
            type="button"
            className="dialog-button"
            onClick={onClose}
            disabled={busy}
            data-testid="import-contact-cancel"
          >
            cancel
          </button>
          <button
            type="submit"
            className="dialog-button dialog-button--primary"
            disabled={busy || code === null}
            data-testid="import-contact-confirm"
          >
            {busy ? 'verifying...' : 'import'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
