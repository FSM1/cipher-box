import { useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useIdentity } from '../auth/IdentityProvider';
import { useAuth } from '../auth/useAuth';
import { EmailLoginForm } from '../components/auth/EmailLoginForm';
import { GoogleLoginButton } from '../components/auth/GoogleLoginButton';
import { LoginError } from '../components/auth/LoginError';
import { RecoveryPhraseLogin } from '../components/auth/RecoveryPhraseLogin';
import { WalletLoginButton } from '../components/auth/WalletLoginButton';
import { MatrixBackground } from '../components/MatrixBackground';
import { StagingBanner } from '../components/StagingBanner';

/**
 * The vault's front door. Every method here is a first login: each mints a
 * CipherBox identity token and reaches the same derived key (ADR 0008).
 */
export function LoginPage() {
  const {
    isAuthenticated,
    isReady,
    isBusy,
    error,
    loginWithGoogle,
    sendEmailCode,
    loginWithEmailCode,
    walletNonce,
    loginWithWallet,
    recoveryRequired,
  } = useAuth();
  const { googleClientId } = useIdentity();
  const navigate = useNavigate();
  const { pathname } = useLocation();

  // Only redirect away from the login route itself, so a late settle cannot yank
  // a user who has already navigated on.
  useEffect(() => {
    if (isAuthenticated && pathname === '/') navigate('/files');
  }, [isAuthenticated, navigate, pathname]);

  // `useAuth` already surfaces the failure as `error`.
  const dispatch = (login: Promise<void>) => void login.catch(() => undefined);

  return (
    <>
      <StagingBanner />
      <div className="login-container">
        <MatrixBackground />
        <div className="login-panel">
          <h1>CipherBox</h1>
          <p className="tagline">zero-knowledge encrypted storage</p>
          <p className="login-description">
            your files, encrypted on your device. we never see your data.
          </p>

          {recoveryRequired ? (
            <RecoveryPhraseLogin />
          ) : (
            <div className="login-methods">
              <GoogleLoginButton
                clientId={googleClientId}
                onCredential={(idToken) => dispatch(loginWithGoogle(idToken))}
                disabled={!isReady}
                busy={isBusy}
              />

              <div className="login-divider">
                <span>// or</span>
              </div>

              <EmailLoginForm
                onSendCode={sendEmailCode}
                onVerify={loginWithEmailCode}
                disabled={!isReady}
                busy={isBusy}
              />

              <div className="login-divider">
                <span>// or</span>
              </div>

              <WalletLoginButton
                requestNonce={walletNonce}
                onLogin={loginWithWallet}
                disabled={!isReady || isBusy}
              />
            </div>
          )}

          {/* The recovery panel renders its own failures beside its own field. */}
          {error && !recoveryRequired && <LoginError message={error} />}
        </div>
        <footer className="login-footer">
          <span className="footer-copyright">(c) 2026 CipherBox</span>
          <a
            href="https://github.com/fsm1/cipher-box"
            className="footer-link"
            target="_blank"
            rel="noopener noreferrer"
          >
            [github]
          </a>
        </footer>
      </div>
    </>
  );
}
