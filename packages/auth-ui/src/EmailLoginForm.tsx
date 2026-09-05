import { useEffect, useRef, useState, type FormEvent } from 'react';

export interface EmailLoginFormProps {
  /** Asks CipherBox to deliver a code; resolves once it is on its way. */
  onSendCode: (email: string) => Promise<void>;
  onVerify: (email: string, code: string) => Promise<void>;
  /** True while the tab cannot accept a login at all. */
  disabled?: boolean;
  /** True while some auth transition is in flight. */
  busy?: boolean;
}

/**
 * CipherBox's own passwordless email (ADR 0008 D1): the address is collected
 * here, and so is the code — there is no provider window in this flow.
 */
export function EmailLoginForm({ onSendCode, onVerify, disabled, busy }: EmailLoginFormProps) {
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [sentTo, setSentTo] = useState<string | null>(null);

  const codeInput = useRef<HTMLInputElement>(null);

  const trimmed = email.trim().toLowerCase();
  const blocked = disabled || busy;

  // The step swaps the field out from under the focused button, so a member on
  // a keyboard or a screen reader would otherwise have to go hunting for it.
  useEffect(() => {
    if (sentTo !== null) codeInput.current?.focus();
  }, [sentTo]);

  // The page renders the failure; this form only advances on success.
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (blocked) return;
    if (sentTo === null) {
      if (!trimmed) return;
      void onSendCode(trimmed).then(
        () => setSentTo(trimmed),
        () => undefined
      );
      return;
    }
    if (code.length === 6) void onVerify(sentTo, code).catch(() => undefined);
  };

  const restart = () => {
    setSentTo(null);
    setCode('');
  };

  return (
    <form onSubmit={submit} className="email-login-form">
      {sentTo === null ? (
        <>
          <label htmlFor="login-email" className="sr-only">
            Email address
          </label>
          <input
            id="login-email"
            data-testid="email-input"
            type="email"
            className="email-login-input"
            placeholder="enter email address"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            disabled={blocked}
            required
            autoComplete="email"
          />
          <button
            type="submit"
            data-testid="email-login-button"
            className={filledButton(busy)}
            disabled={blocked || !trimmed}
            aria-busy={busy}
          >
            {busy ? 'sending code...' : '[CONTINUE]'}
          </button>
        </>
      ) : (
        <>
          <p className="email-login-sent" aria-live="polite">
            // code sent to {sentTo}
          </p>
          <label htmlFor="login-code" className="sr-only">
            Verification code
          </label>
          <input
            id="login-code"
            ref={codeInput}
            data-testid="email-code-input"
            type="text"
            className="email-login-input"
            placeholder="enter 6-digit code"
            value={code}
            onChange={(event) => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
            disabled={blocked}
            required
            autoComplete="one-time-code"
            inputMode="numeric"
            maxLength={6}
          />
          <button
            type="submit"
            data-testid="email-verify-button"
            className={filledButton(busy)}
            disabled={blocked || code.length !== 6}
            aria-busy={busy}
          >
            {busy ? 'verifying...' : '[VERIFY]'}
          </button>
          <button
            type="button"
            data-testid="email-restart-button"
            className="email-login-restart"
            onClick={restart}
            disabled={blocked}
          >
            // use a different address
          </button>
        </>
      )}
    </form>
  );
}

function filledButton(busy?: boolean): string {
  return busy
    ? 'terminal-btn terminal-btn--filled terminal-btn--loading'
    : 'terminal-btn terminal-btn--filled';
}
