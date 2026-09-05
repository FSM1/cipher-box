import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { GOOGLE_CLIENT_ID_ENV } from '../../engine/config';
import { errorMessage } from '../../lib/errorMessage';
import { LoginError } from '@cipherbox/auth-ui';

/** The slice of Google Identity Services this component drives. */
interface GoogleIdentityServices {
  accounts: {
    id: {
      initialize(config: {
        client_id: string;
        callback: (response: { credential: string }) => void;
        auto_select: boolean;
      }): void;
      renderButton(
        parent: HTMLElement,
        options: { theme: string; size: string; text: string; shape: string; width: number }
      ): void;
    };
  };
}

const GIS_SRC = 'https://accounts.google.com/gsi/client';

/**
 * One load per document, shared across mounts: React StrictMode mounts twice
 * and the script installs a global.
 */
let gisLoad: Promise<GoogleIdentityServices> | null = null;

/** The SDK once it has installed its global, and `null` until then. */
function installedGis(): GoogleIdentityServices | null {
  const installed = (globalThis as { google?: GoogleIdentityServices }).google;
  return installed?.accounts?.id ? installed : null;
}

function loadGoogleIdentityServices(): Promise<GoogleIdentityServices> {
  gisLoad ??= new Promise<GoogleIdentityServices>((resolve, reject) => {
    const existing = installedGis();
    if (existing) {
      resolve(existing);
      return;
    }
    const script = document.createElement('script');
    script.src = GIS_SRC;
    script.async = true;
    script.onload = () => {
      const loaded = installedGis();
      if (loaded) resolve(loaded);
      else reject(new Error('google sign-in loaded but did not install'));
    };
    script.onerror = () => reject(new Error('google sign-in could not be loaded'));
    document.head.appendChild(script);
  }).catch((failure: unknown) => {
    // A failed load must not be cached as permanent — a reload should retry.
    gisLoad = null;
    throw failure;
  });
  return gisLoad;
}

interface GoogleLoginButtonProps {
  /** The OAuth provider's client ID, not the Web3Auth project's. */
  clientId: string | undefined;
  /** Receives the Google ID token; the API verifies it. */
  onCredential: (idToken: string) => void;
  /** True while the tab cannot accept a login at all. */
  disabled?: boolean;
  /** True while some auth transition is in flight. */
  busy?: boolean;
}

/**
 * Collects a Google ID token with Google's own rendered button. A build that
 * carries no client ID presents the method as unavailable instead, so the
 * affordance cannot be clicked into nothing.
 */
export function GoogleLoginButton({
  clientId,
  onCredential,
  disabled,
  busy,
}: GoogleLoginButtonProps) {
  const target = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);
  // Read through a ref so a re-rendered parent cannot re-run the one-shot mount.
  // GIS calls it from outside React, so it is installed on commit: a render
  // React discards must not leave its callback reachable.
  const deliver = useRef(onCredential);
  useLayoutEffect(() => {
    deliver.current = onCredential;
  }, [onCredential]);

  useEffect(() => {
    if (!clientId) return;
    let live = true;
    loadGoogleIdentityServices().then(
      (google) => {
        if (!live || !target.current) return;
        google.accounts.id.initialize({
          client_id: clientId,
          callback: (response) => deliver.current(response.credential),
          auto_select: false,
        });
        google.accounts.id.renderButton(target.current, {
          theme: 'filled_black',
          size: 'large',
          text: 'continue_with',
          shape: 'rectangular',
          width: 280,
        });
      },
      (failure: unknown) => {
        if (live) setError(errorMessage(failure));
      }
    );
    return () => {
      live = false;
    };
  }, [clientId]);

  if (!clientId) {
    return (
      <div className="google-login-wrapper">
        <div className="google-login-unavailable" data-testid="google-login-unavailable">
          google sign-in is unavailable — this build is missing {GOOGLE_CLIENT_ID_ENV}
        </div>
      </div>
    );
  }

  // The target outlives every busy cycle: GIS renders into this node once, and
  // unmounting it would hand the next render an empty div nothing renders into
  // again. So the transition is an overlay, not a replacement.
  return (
    <div className="google-login-wrapper">
      <div
        ref={target}
        data-testid="google-login-button"
        className={targetClass(disabled, busy)}
        aria-disabled={disabled || busy}
        aria-hidden={busy}
      />
      {busy && (
        <div className="google-login-status" aria-live="polite">
          authenticating with google...
        </div>
      )}
      {error && <LoginError message={error} />}
    </div>
  );
}

function targetClass(disabled?: boolean, busy?: boolean): string {
  const classes = ['google-login-target'];
  if (disabled) classes.push('is-disabled');
  if (busy) classes.push('is-busy');
  return classes.join(' ');
}
