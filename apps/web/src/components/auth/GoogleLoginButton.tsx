interface GoogleLoginButtonProps {
  onLogin: () => void;
  /** True while the tab cannot accept a login at all. */
  disabled?: boolean;
  /** True while some auth transition is in flight. */
  busy?: boolean;
}

/** Starts Core Kit's Google flow; Web3Auth owns the popup and the OAuth round-trip. */
export function GoogleLoginButton({ onLogin, disabled, busy }: GoogleLoginButtonProps) {
  return (
    <button
      type="button"
      data-testid="google-login-button"
      className={busy ? 'terminal-btn terminal-btn--loading' : 'terminal-btn'}
      onClick={onLogin}
      disabled={disabled || busy}
      aria-label="Sign in with Google"
      aria-busy={busy}
    >
      {busy ? 'authenticating with google...' : '[GOOGLE]'}
    </button>
  );
}
