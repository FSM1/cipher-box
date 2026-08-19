import { useEffect, useRef, useState } from 'react';
import { normalizeRecoveryPhrase, RECOVERY_PHRASE_WORDS } from '../../auth/coreKit';
import { useAuth } from '../../auth/useAuth';
import { LoginError } from './LoginError';

/**
 * The recovery phrase as a login (ADR 0009 D2). The field is uncontrolled and
 * blanked on submit: a phrase kept in component state would outlive the attempt
 * in a React tree the member can no longer see.
 */
export function RecoveryPhraseLogin() {
  const { loginWithRecoveryPhrase, cancelRecovery, isBusy, error } = useAuth();
  const field = useRef<HTMLTextAreaElement>(null);
  const [malformed, setMalformed] = useState<string | null>(null);

  // The panel replaces the login methods in place and `isBusy` disables the
  // field, so focus lands on the body unless it is put back each time.
  useEffect(() => {
    if (!isBusy) field.current?.focus();
  }, [isBusy]);

  const submit = async () => {
    const input = field.current;
    if (!input) return;
    const phrase = normalizeRecoveryPhrase(input.value);
    // Read once and dropped, whatever the attempt turns out to be: a browser's
    // crash-recovery snapshot persists form-field values to the profile
    // directory, and retyping is cheaper than a phrase written to disk.
    input.value = '';
    if (phrase.split(' ').filter(Boolean).length !== RECOVERY_PHRASE_WORDS) {
      setMalformed(`a recovery phrase is ${String(RECOVERY_PHRASE_WORDS)} words`);
      return;
    }
    setMalformed(null);
    try {
      await loginWithRecoveryPhrase(phrase);
    } catch {
      // `useAuth` already surfaces the failure as `error`.
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
        aria-label="recovery phrase"
        disabled={isBusy}
      />
      <div className="recovery-actions">
        <button
          type="button"
          className={
            isBusy
              ? 'terminal-btn terminal-btn--filled terminal-btn--loading'
              : 'terminal-btn terminal-btn--filled'
          }
          data-testid="recovery-submit"
          disabled={isBusy}
          onClick={() => void submit()}
        >
          {isBusy ? 'unlocking...' : 'unlock'}
        </button>
        <button
          type="button"
          className="email-login-restart"
          data-testid="recovery-cancel"
          disabled={isBusy}
          onClick={() => void cancelRecovery()}
        >
          cancel
        </button>
      </div>
      {message && <LoginError message={message} />}
    </div>
  );
}
