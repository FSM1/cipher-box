import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { StatusIndicator } from '../components/layout';
import { GoogleLoginButton } from '../components/auth/GoogleLoginButton';
import { EmailLoginForm } from '../components/auth/EmailLoginForm';
import { WalletLoginButton } from '../components/auth/WalletLoginButton';
import { DeviceWaitingScreen } from '../components/mfa/DeviceWaitingScreen';
import { RecoveryInput } from '../components/mfa/RecoveryInput';
import { MatrixBackground } from '../components/MatrixBackground';
import { StagingBanner } from '../components/StagingBanner';
import { useHealthControllerCheck } from '../api/health/health';
import { useAuth } from '../hooks/useAuth';

type MfaView = 'waiting' | 'recovery';

/**
 * Login page with terminal aesthetic and matrix background.
 * CipherBox-branded custom login UI with Google OAuth and email OTP.
 *
 * When REQUIRED_SHARE is detected (MFA enabled, new device), switches
 * to either DeviceWaitingScreen or RecoveryInput instead of the login form.
 */
export function Login() {
  const {
    isAuthenticated,
    isLoading,
    isRequiredShare,
    completeRequiredShare,
    loginWithGoogle,
    loginWithEmail,
    loginWithWallet,
  } = useAuth();
  const navigate = useNavigate();
  const [loginError, setLoginError] = useState<string | null>(null);
  const [mfaView, setMfaView] = useState<MfaView>('waiting');

  // Health check for disabling connect button when API is down
  const {
    data: healthData,
    isLoading: isHealthLoading,
    isError: isHealthError,
  } = useHealthControllerCheck({
    query: {
      refetchInterval: 30000,
      retry: 2,
      refetchOnWindowFocus: true,
    },
  });

  const isApiDown = !isHealthLoading && (isHealthError || healthData?.status !== 'ok');

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/files');
    }
  }, [isAuthenticated, navigate]);

  const handleGoogleLogin = useCallback(
    async (googleIdToken: string) => {
      setLoginError(null);
      try {
        await loginWithGoogle(googleIdToken);
      } catch (err) {
        setLoginError(err instanceof Error ? err.message : 'Google login failed');
      }
    },
    [loginWithGoogle]
  );

  const handleEmailLogin = useCallback(
    async (email: string, otp: string) => {
      setLoginError(null);
      try {
        await loginWithEmail(email, otp);
      } catch (err) {
        setLoginError(err instanceof Error ? err.message : 'Email login failed');
      }
    },
    [loginWithEmail]
  );

  const handleWalletLogin = useCallback(
    async (idToken: string, userId: string) => {
      setLoginError(null);
      try {
        await loginWithWallet(idToken, userId);
      } catch (err) {
        setLoginError(err instanceof Error ? err.message : 'Wallet login failed');
      }
    },
    [loginWithWallet]
  );

  const handleRecoveryFallback = useCallback(() => {
    setMfaView('recovery');
  }, []);

  const handleBackToWaiting = useCallback(() => {
    setMfaView('waiting');
  }, []);

  const handleRecoveryComplete = useCallback(async () => {
    // Recovery succeeded: Core Kit is now LOGGED_IN.
    // completeRequiredShare() will do backend auth + vault load + navigate.
    await completeRequiredShare();
  }, [completeRequiredShare]);

  const handleApprovalComplete = useCallback(() => {
    // Approval flow already called completeRequiredShare() inside the hook.
    // Nothing extra needed here -- navigation happens in completeRequiredShare.
  }, []);

  // Show loading state while checking authentication
  if (isLoading) {
    return (
      <>
        <StagingBanner variant="login" />
        <div className="login-container">
          <MatrixBackground opacity={0.3} frameInterval={50} />
          <div className="loading">initializing...</div>
          <LoginFooter />
        </div>
      </>
    );
  }

  // REQUIRED_SHARE state: show MFA challenge UI instead of login form
  if (isRequiredShare) {
    return (
      <>
        <StagingBanner variant="login" />
        <div className="login-container">
          <MatrixBackground opacity={0.3} frameInterval={50} />
          {mfaView === 'waiting' ? (
            <DeviceWaitingScreen
              onRecoveryFallback={handleRecoveryFallback}
              onApprovalComplete={handleApprovalComplete}
            />
          ) : (
            <RecoveryInput
              onRecoveryComplete={handleRecoveryComplete}
              onBack={handleBackToWaiting}
            />
          )}
          <LoginFooter />
        </div>
      </>
    );
  }

  return (
    <>
      <StagingBanner variant="login" />
      <div className="login-container">
        <MatrixBackground opacity={0.3} frameInterval={50} />
        <div className="login-panel">
          <h1>CIPHERBOX</h1>
          <p className="tagline">zero-knowledge encrypted storage</p>
          <p className="login-description">
            your files, encrypted on your device. we never see your data.
          </p>

          <div className="login-methods">
            <GoogleLoginButton onLogin={handleGoogleLogin} disabled={isLoading || isApiDown} />

            <div className="login-divider">
              <span>{'// or'}</span>
            </div>

            <EmailLoginForm onLogin={handleEmailLogin} disabled={isLoading || isApiDown} />

            <div className="login-divider">
              <span>{'// or'}</span>
            </div>

            <WalletLoginButton onLogin={handleWalletLogin} disabled={isLoading || isApiDown} />
          </div>

          {loginError && (
            <div className="login-error" role="alert" aria-live="polite">
              {loginError}
            </div>
          )}
        </div>
        <LoginFooter />
      </div>
    </>
  );
}

/** Shared footer to avoid duplication across login states. */
function LoginFooter() {
  return (
    <footer className="login-footer">
      <div className="footer-left">
        <span className="footer-copyright">(c) 2026 CipherBox</span>
      </div>
      <div className="footer-center">
        <a href="#" className="footer-link">
          [help]
        </a>
        <a href="#" className="footer-link">
          [privacy]
        </a>
        <a href="#" className="footer-link">
          [terms]
        </a>
        <a
          href="https://github.com/fsm1/cipher-box"
          className="footer-link"
          target="_blank"
          rel="noopener noreferrer"
        >
          [github]
        </a>
      </div>
      <div className="footer-right">
        <StatusIndicator />
      </div>
    </footer>
  );
}
