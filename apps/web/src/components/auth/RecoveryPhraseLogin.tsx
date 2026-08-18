import { useRef, useState } from 'react';
import { useAuth } from '../../auth/useAuth';
import { LoginError } from './LoginError';

const WORDS = 24;

/**
 * The recovery phrase as a login (ADR 0009 D2). The field is uncontrolled and
 * blanked on submit: a phrase kept in component state would outlive the attempt
 * in a React tree the member can no longer see.
 */
export function RecoveryPhraseLogin() {
  const { loginWithRecoveryPhrase, cancelRecovery, isBusy, error } = useAuth();
  const field = useRef<HTMLTextAreaElement>(null);
  const [malformed, setMalformed] = useState<string | null>(null);

  const submit = async () => {
    const input = field.current;
    if (!input) return;
    const phrase = input.value.trim().replace(/\s+/g, ' ');
    if (phrase.split(' ').filter(Boolean).length !== WORDS) {
      setMalformed(`a recovery phrase is ${WORDS} words`);
      return;
    }
    setMalformed(null);
    try {
      await loginWithRecoveryPhrase(phrase);
      input.value = '';
    } catch {
      // `useAuth` already surfaces the failure as `error`; the field keeps what
      // was typed so a mistyped word can be corrected rather than retyped.
    }
  };

  return (
    <div className="recovery-panel" data-testid="recovery-login">
      <h2>recovery phrase</h2>
      <p className="login-description">
        this device holds no key for your account. enter the {WORDS}-word phrase you saved when you
        turned the recovery phrase on.
      </p>
      <textarea
        ref={field}
        className="recovery-input"
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
          className="login-button"
          data-testid="recovery-submit"
          disabled={isBusy}
          onClick={() => void submit()}
        >
          {isBusy ? 'unlocking...' : 'unlock'}
        </button>
        <button
          type="button"
          className="recovery-cancel"
          data-testid="recovery-cancel"
          disabled={isBusy}
          onClick={() => void cancelRecovery()}
        >
          cancel
        </button>
      </div>
      {(malformed ?? error) && <LoginError message={malformed ?? error!} />}
    </div>
  );
}
