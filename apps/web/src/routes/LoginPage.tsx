import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useIdentity } from '../auth/IdentityProvider';
import { useAuth } from '../auth/useAuth';
import { DeviceApprovalWait } from '../components/auth/DeviceApprovalWait';
import { EmailLoginForm } from '../components/auth/EmailLoginForm';
import { GoogleLoginButton } from '../components/auth/GoogleLoginButton';
import { LoginError } from '../components/auth/LoginError';
import { RecoveryPhraseLogin } from '../components/auth/RecoveryPhraseLogin';
import { SignedInElsewhere } from '../components/auth/SignedInElsewhere';
import { WalletLoginButton } from '../components/auth/WalletLoginButton';
import { MatrixBackground } from '../components/MatrixBackground';
import { StagingBanner } from '../components/StagingBanner';

/**
 * How a login held at the factor policy is finished. Both routes end the same
 * way; the phrase is the one that needs no second device (ADR 0009 D2).
 */
type RecoveryRoute = 'choose' | 'approve' | 'phrase';

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
    heldElsewhere,
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
  const [route, setRoute] = useState<RecoveryRoute>('choose');

  // Only redirect away from the login route itself, so a late settle cannot yank
  // a user who has already navigated on.
  useEffect(() => {
    if (isAuthenticated && pathname === '/') navigate('/files');
  }, [isAuthenticated, navigate, pathname]);

  // A resolved prompt leaves no route behind, so the next one starts at the ask.
  useEffect(() => {
    if (!recoveryRequired) setRoute('choose');
  }, [recoveryRequired]);

  // `useAuth` already surfaces the failure as `error`.
  const dispatch = (login: Promise<void>) => void login.catch(() => undefined);

  function heldAtPolicy() {
    if (route === 'phrase') return <RecoveryPhraseLogin />;
    if (route === 'approve') {
      return (
        <DeviceApprovalWait
          onUseRecoveryPhrase={() => setRoute('phrase')}
          onCancel={() => setRoute('choose')}
        />
      );
    }
    return (
      <div className="recovery-panel" data-testid="recovery-choice">
        <h2>one more step</h2>
        <p className="login-description">
          this device holds no key for your account. approve it from a device you already use, or
          enter your recovery phrase.
        </p>
        <div className="recovery-actions">
          <button
            type="button"
            className="terminal-btn terminal-btn--filled"
            onClick={() => setRoute('approve')}
            data-testid="recovery-choose-approve"
          >
            approve from a device you already use
          </button>
          <button
            type="button"
            className="terminal-btn"
            onClick={() => setRoute('phrase')}
            data-testid="recovery-choose-phrase"
          >
            use your recovery phrase
          </button>
        </div>
      </div>
    );
  }

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
            heldAtPolicy()
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

          {heldElsewhere && <SignedInElsewhere heldBy={heldElsewhere.heldBy} />}
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
