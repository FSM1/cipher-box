import { useState, type FormEvent } from 'react';

interface EmailLoginFormProps {
  onLogin: (email: string) => void;
  /** True while the tab cannot accept a login at all. */
  disabled?: boolean;
  /** True while some auth transition is in flight. */
  busy?: boolean;
}

/**
 * Collects the address Core Kit's passwordless flow sends its code to; the code
 * itself is entered in Web3Auth's own window.
 */
export function EmailLoginForm({ onLogin, disabled, busy }: EmailLoginFormProps) {
  const [email, setEmail] = useState('');
  const trimmed = email.trim().toLowerCase();
  const blocked = disabled || busy;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (trimmed && !blocked) onLogin(trimmed);
  };

  return (
    <form onSubmit={submit} className="email-login-form">
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
        className={
          busy
            ? 'terminal-btn terminal-btn--filled terminal-btn--loading'
            : 'terminal-btn terminal-btn--filled'
        }
        disabled={blocked || !trimmed}
        aria-busy={busy}
      >
        {busy ? 'sending code...' : '[CONTINUE]'}
      </button>
    </form>
  );
}
