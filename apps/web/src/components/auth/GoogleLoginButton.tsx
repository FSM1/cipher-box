import { useCallback, useEffect, useRef, useState } from 'react';

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
      renderButton: (
        parent: HTMLElement,
        options: {
          theme?: 'outline' | 'filled_blue' | 'filled_black';
          size?: 'large' | 'medium' | 'small';
          width?: number;
          text?: 'signin_with' | 'signup_with' | 'continue_with' | 'signin';
          shape?: 'rectangular' | 'pill' | 'circle' | 'square';
        }
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
 * and triggers the Google One Tap flow on click.
 *
 * If One Tap is blocked (e.g. Brave browser), falls back to Google's native
 * Sign In button which uses a standard OAuth popup.
 */
export function GoogleLoginButton({ onLogin, disabled }: GoogleLoginButtonProps) {
  const [gisLoaded, setGisLoaded] = useState(false);
  const [ready, setReady] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showNativeButton, setShowNativeButton] = useState(false);
  const nativeButtonRef = useRef<HTMLDivElement>(null);

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

  // Render native Google button when fallback is needed
  useEffect(() => {
    if (!showNativeButton || !ready || !nativeButtonRef.current) return;

    // Re-initialize to ensure the callback is current
    google.accounts.id.initialize({
      client_id: clientId!,
      callback: (response: { credential: string }) => {
        setLoading(true);
        handleCredentialResponse(response);
      },
      auto_select: false,
    });

    google.accounts.id.renderButton(nativeButtonRef.current, {
      theme: 'filled_black',
      size: 'large',
      width: 300,
      text: 'continue_with',
      shape: 'rectangular',
    });
  }, [showNativeButton, ready, clientId, handleCredentialResponse]);

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
        setLoading(false);
        // Fall back to native Google button (standard OAuth popup)
        setShowNativeButton(true);
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
      {!showNativeButton && (
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
      )}
      {showNativeButton && (
        <div
          ref={nativeButtonRef}
          className="google-native-btn-container"
          data-testid="google-native-button"
        />
      )}
      {error && (
        <div className="login-error" role="alert" aria-live="polite">
          {error}
        </div>
      )}
    </div>
  );
}
