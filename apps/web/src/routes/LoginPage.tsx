import { useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/useAuth';
import { EmailLoginForm } from '../components/auth/EmailLoginForm';
import { GoogleLoginButton } from '../components/auth/GoogleLoginButton';
import { WalletLoginButton } from '../components/auth/WalletLoginButton';
import { MatrixBackground } from '../components/MatrixBackground';
import { StagingBanner } from '../components/StagingBanner';
import { apiBaseUrl } from '../engine/config';

/**
 * The vault's front door: the Core Kit methods plus SIWE
 * (blueprint/web-client.md "Composition"). Every method ends in the same place
 * — the engine holds the session; this page holds no key, token, or vault state.
 */
export function LoginPage() {
  const {
    isAuthenticated,
    isReady,
    isBusy,
    error,
    loginWithGoogle,
    loginWithEmail,
    loginWithWallet,
  } = useAuth();
  const navigate = useNavigate();
  const { pathname } = useLocation();

  // Only redirect away from the login route itself, so a late settle cannot yank
  // a user who has already navigated on.
  useEffect(() => {
    if (isAuthenticated && pathname === '/') navigate('/files');
  }, [isAuthenticated, navigate, pathname]);

  const swallow = (login: Promise<void>) => void login.catch(() => undefined);

  return (
    <>
      <StagingBanner />
      <div className="login-container">
        <MatrixBackground opacity={0.3} frameInterval={50} />
        <div className="login-panel">
          <h1>CipherBox</h1>
          <p className="tagline">zero-knowledge encrypted storage</p>
          <p className="login-description">
            your files, encrypted on your device. we never see your data.
          </p>

          <div className="login-methods">
            <GoogleLoginButton
              onLogin={() => swallow(loginWithGoogle())}
              disabled={!isReady || isBusy}
              busy={isBusy}
            />

            <div className="login-divider">
              <span>{'// or'}</span>
            </div>

            <EmailLoginForm
              onLogin={(email) => swallow(loginWithEmail(email))}
              disabled={!isReady || isBusy}
              busy={isBusy}
            />

            <div className="login-divider">
              <span>{'// or'}</span>
            </div>

            <WalletLoginButton
              onLogin={loginWithWallet}
              apiBaseUrl={apiBaseUrl(import.meta.env)}
              disabled={!isReady || isBusy}
            />
          </div>

          {error && (
            <div className="login-error" role="alert" aria-live="polite">
              {error}
            </div>
          )}
        </div>
        <footer className="login-footer">
          <div className="footer-left">
            <span className="footer-copyright">(c) 2026 CipherBox</span>
          </div>
          <div className="footer-center">
            <a
              href="https://github.com/fsm1/cipher-box"
              className="footer-link"
              target="_blank"
              rel="noopener noreferrer"
            >
              [github]
            </a>
          </div>
        </footer>
      </div>
    </>
  );
}
