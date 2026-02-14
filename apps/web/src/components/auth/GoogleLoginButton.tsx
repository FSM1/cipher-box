import { useCallback, useEffect, useState } from 'react';

/** Minimal type declarations for Google Identity Services (GIS) library */
declare const google: {
  accounts: {
    id: {
      initialize: (config: {
        client_id: string;
        callback: (response: { credential: string }) => void;
        auto_select: boolean;
      }) => void;
      prompt: (
        momentListener?: (notification: {
          isNotDisplayed: () => boolean;
          isSkippedMoment: () => boolean;
        }) => void
      ) => void;
    };
  };
};

interface GoogleLoginButtonProps {
  onLogin: (googleIdToken: string) => Promise<void>;
  disabled?: boolean;
}

/**
 * Google OAuth login button using Google Identity Services (GIS) library.
 * Loads the GIS script dynamically, initializes with VITE_GOOGLE_CLIENT_ID,
 * and triggers the Google One Tap / popup flow on click.
 *
 * If VITE_GOOGLE_CLIENT_ID is not set, renders in a disabled state.
 */
export function GoogleLoginButton({ onLogin, disabled }: GoogleLoginButtonProps) {
  const [gisLoaded, setGisLoaded] = useState(false);
  const [ready, setReady] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined;

  // Handle credential response from Google
  const handleCredentialResponse = useCallback(
    async (response: { credential: string }) => {
      try {
        await onLogin(response.credential);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Google login failed');
      } finally {
        setLoading(false);
      }
    },
    [onLogin]
  );

  // Load GIS script dynamically on mount
  useEffect(() => {
    if (!clientId) return;

    // Check if already loaded
    if (typeof google !== 'undefined' && google?.accounts?.id) {
      setGisLoaded(true);
      return;
    }

    let cancelled = false;

    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.onload = () => {
      if (!cancelled) setGisLoaded(true);
    };
    script.onerror = () => {
      if (!cancelled) setError('Failed to load Google authentication');
    };
    document.body.appendChild(script);

    return () => {
      cancelled = true;
      if (script.parentNode) {
        document.body.removeChild(script);
      }
    };
  }, [clientId]);

  // Initialize GIS once script loads
  useEffect(() => {
    if (!gisLoaded || !clientId) return;

    try {
      google.accounts.id.initialize({
        client_id: clientId,
        callback: handleCredentialResponse,
        auto_select: false,
      });
      setReady(true);
    } catch {
      setError('Failed to initialize Google authentication');
    }
  }, [gisLoaded, clientId, handleCredentialResponse]);

  const handleClick = () => {
    if (!ready || disabled || loading) return;

    setLoading(true);
    setError(null);

    // Safety timeout: if Google prompt doesn't resolve within 60s
    // (e.g., user closes popup without selecting), reset loading state
    const timeoutId = setTimeout(() => {
      setLoading(false);
    }, 60000);

    const originalHandleCredential = handleCredentialResponse;
    const wrappedHandler = async (response: { credential: string }) => {
      clearTimeout(timeoutId);
      await originalHandleCredential(response);
    };

    // Re-initialize with wrapped handler to clear timeout on success
    google.accounts.id.initialize({
      client_id: clientId!,
      callback: wrappedHandler,
      auto_select: false,
    });

    google.accounts.id.prompt((notification) => {
      if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
        clearTimeout(timeoutId);
        setError('Google popup was blocked. Please allow popups for this site.');
        setLoading(false);
      }
    });
  };

  const isDisabled = disabled || loading || !clientId || (!ready && !!clientId);

  const buttonText = () => {
    if (!clientId) return '[GOOGLE - NOT CONFIGURED]';
    if (loading) return 'authenticating with google...';
    return '[GOOGLE]';
  };

  return (
    <div className="google-login-wrapper">
      <button
        type="button"
        data-testid="google-login-button"
        className={[
          'google-login-btn',
          loading ? 'google-login-btn--loading' : '',
          !clientId ? 'google-login-btn--not-configured' : '',
        ]
          .filter(Boolean)
          .join(' ')}
        onClick={handleClick}
        disabled={isDisabled}
        aria-label="Sign in with Google"
        aria-busy={loading}
      >
        {buttonText()}
      </button>
      {error && (
        <div className="login-error" role="alert" aria-live="polite">
          {error}
        </div>
      )}
    </div>
  );
}
