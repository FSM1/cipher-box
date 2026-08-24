import { useMemo, useState, type FormEvent } from 'react';
import { MAX_PASTED_CHARS, parseContactCode } from '../../sharing/contactCode';

interface ContactImportFormProps {
  busy: boolean;
  onCancel: () => void;
  onConfirm: (contactCode: Uint8Array) => void;
}

/**
 * Takes a contact code by paste and hands its bytes on. Identity keys arrive
 * only out-of-band (blueprint/api.md "Contact exchange") and the code
 * authenticates itself, so this reads nothing inside it.
 */
export function ContactImportForm({ busy, onCancel, onConfirm }: ContactImportFormProps) {
  const [pasted, setPasted] = useState('');
  // Memoized: a mis-paste can be arbitrarily long, and this runs per keystroke.
  const code = useMemo(() => parseContactCode(pasted), [pasted]);
  const unreadable = pasted.trim() !== '' && code === null;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!busy && code !== null) onConfirm(code);
  };

  return (
    <form className="dialog-content" onSubmit={submit} data-testid="import-contact-form">
      <label className="dialog-label" htmlFor="import-contact-code">
        contact code
      </label>
      <textarea
        id="import-contact-code"
        className="dialog-input sharing-code-field"
        value={pasted}
        maxLength={MAX_PASTED_CHARS}
        onChange={(event) => setPasted(event.target.value)}
        disabled={busy}
        autoComplete="off"
        spellCheck={false}
        autoFocus
      />
      {unreadable && (
        <p className="sharing-note" data-testid="import-contact-unreadable">
          {'// that is not a contact code — paste it exactly as it was sent'}
        </p>
      )}
      <div className="dialog-actions">
        <button
          type="button"
          className="dialog-button"
          onClick={onCancel}
          disabled={busy}
          data-testid="import-contact-cancel"
        >
          back
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
  );
}
