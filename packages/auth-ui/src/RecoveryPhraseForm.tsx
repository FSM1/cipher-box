import { useEffect, useRef, useState } from 'react';
import {
  isRecoveryPhraseWellFormed,
  normalizeRecoveryPhrase,
  RECOVERY_PHRASE_WORDS,
} from '@cipherbox/login';
import { LoginError } from './LoginError';

export interface RecoveryPhraseFormProps {
  /** Redeems the normalized phrase. The host reports a refusal as `error`. */
  onSubmit: (phrase: string) => Promise<void>;
  /**
   * Abandons the held login. The Core Kit session behind this prompt is a live
   * credential, so leaving the panel must end it rather than hide it.
   */
  onCancel: () => void;
  /** True while the host has an auth transition in flight. */
  busy: boolean;
  /** What the host's last attempt reported; the word count is this form's own. */
  error: string | null;
}

/**
 * The recovery phrase as a login (ADR 0009 D2). The field is uncontrolled and
 * blanked on submit: a phrase kept in component state would outlive the attempt
 * in a tree the member can no longer see, and a browser's crash-recovery
 * snapshot persists form-field values to the profile directory.
 */
export function RecoveryPhraseForm({ onSubmit, onCancel, busy, error }: RecoveryPhraseFormProps) {
  const field = useRef<HTMLTextAreaElement>(null);
  const [malformed, setMalformed] = useState<string | null>(null);

  // The panel replaces the login methods in place and `busy` disables the
  // field, so focus lands on the body unless it is put back each time.
  useEffect(() => {
    if (!busy) field.current?.focus();
  }, [busy]);

  const submit = async () => {
    const input = field.current;
    if (input === null) return;
    const phrase = normalizeRecoveryPhrase(input.value);
    // Read once and dropped, whatever the attempt turns out to be.
    input.value = '';
    if (!isRecoveryPhraseWellFormed(phrase)) {
      setMalformed(`a recovery phrase is ${String(RECOVERY_PHRASE_WORDS)} words`);
      return;
    }
    setMalformed(null);
    try {
      await onSubmit(phrase);
    } catch {
      // The host surfaces the failure as `error`.
    }
  };

  const message = malformed ?? error;

  return (
    <div className="recovery-panel" data-testid="recovery-login">
      <h2>recovery phrase</h2>
      <p className="login-description">
        this device holds no key for your account. enter the {RECOVERY_PHRASE_WORDS}-word phrase you
        saved when you turned the recovery phrase on.
      </p>
      <textarea
        ref={field}
        className="email-login-input recovery-input"
        data-testid="recovery-phrase-input"
        rows={4}
        spellCheck={false}
        autoComplete="off"
        // A substitution that rewrites one BIP39 word turns a good phrase into
        // a refusal the member cannot explain.
        autoCorrect="off"
        autoCapitalize="off"
        aria-label="recovery phrase"
        disabled={busy}
      />
      <div className="recovery-actions">
        <button
          type="button"
          className={
            busy
              ? 'terminal-btn terminal-btn--filled terminal-btn--loading'
              : 'terminal-btn terminal-btn--filled'
          }
          data-testid="recovery-submit"
          disabled={busy}
          onClick={() => void submit()}
        >
          {busy ? 'unlocking...' : 'unlock'}
        </button>
        <button
          type="button"
          className="email-login-restart"
          data-testid="recovery-cancel"
          disabled={busy}
          onClick={onCancel}
        >
          cancel
        </button>
      </div>
      {message !== null && <LoginError message={message} />}
    </div>
  );
}
