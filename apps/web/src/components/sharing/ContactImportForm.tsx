import { useMemo, useState, type FormEvent } from 'react';
import { MAX_PASTED_CHARS, parseContactCode } from '../../sharing/contactCode';
import { CopyableValue } from '../file-browser/details/DetailsPrimitives';

interface ContactImportFormProps {
  busy: boolean;
  /** Hex, or `null` until a sharing read has landed (`stores/sharing.store`). */
  ownContactCode: string | null;
  onCancel: () => void;
  onConfirm: (contactCode: Uint8Array) => void;
}

/**
 * Both halves of a contact exchange: the code this member hands over, and the
 * peer's code by paste. Identity keys arrive only out-of-band
 * (blueprint/api.md "Contact exchange") and each code authenticates itself, so
 * this reads nothing inside either one.
 */
export function ContactImportForm({
  busy,
  ownContactCode,
  onCancel,
  onConfirm,
}: ContactImportFormProps) {
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
      <p className="dialog-label">your contact code</p>
      {ownContactCode === null ? (
        <p className="sharing-note">{'// no read has landed yet'}</p>
      ) : (
        <div data-testid="own-contact-code">
          <CopyableValue value={ownContactCode} label="your contact code" />
          <p className="sharing-note">{'// send this to them — an exchange needs both codes'}</p>
        </div>
      )}

      <label className="dialog-label" htmlFor="import-contact-code">
        their contact code
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
