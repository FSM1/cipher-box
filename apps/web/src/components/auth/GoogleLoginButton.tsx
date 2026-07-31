interface GoogleLoginButtonProps {
  onLogin: () => void;
  disabled?: boolean;
  busy?: boolean;
}

/**
 * Starts Core Kit's Google flow. Web3Auth owns the popup and the OAuth
 * round-trip, so this button carries no client id and no provider script.
 */
export function GoogleLoginButton({ onLogin, disabled, busy }: GoogleLoginButtonProps) {
  return (
    <button
      type="button"
      data-testid="google-login-button"
      className={busy ? 'google-login-btn google-login-btn--loading' : 'google-login-btn'}
      onClick={onLogin}
      disabled={disabled}
      aria-label="Sign in with Google"
      aria-busy={busy}
    >
      {busy ? 'authenticating with google...' : '[GOOGLE]'}
    </button>
  );
}
