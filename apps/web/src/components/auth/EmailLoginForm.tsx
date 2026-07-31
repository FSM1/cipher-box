import { useState, type FormEvent } from 'react';

interface EmailLoginFormProps {
  onLogin: (email: string) => void;
  disabled?: boolean;
  busy?: boolean;
}

/**
 * Collects the address Core Kit's passwordless flow sends its code to. The code
 * itself is entered in Web3Auth's own window, so there is no second step here.
 */
export function EmailLoginForm({ onLogin, disabled, busy }: EmailLoginFormProps) {
  const [email, setEmail] = useState('');
  const trimmed = email.trim().toLowerCase();

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (trimmed) onLogin(trimmed);
  };

  return (
    <form onSubmit={submit} className="email-login-form">
      <div className="email-login-step">
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
          disabled={disabled}
          required
          autoComplete="email"
        />
        <button
          type="submit"
          data-testid="email-login-button"
          className={busy ? 'email-login-submit email-login-submit--loading' : 'email-login-submit'}
          disabled={disabled || !trimmed}
          aria-busy={busy}
        >
          {busy ? 'sending code...' : '[CONTINUE]'}
        </button>
      </div>
    </form>
  );
}
