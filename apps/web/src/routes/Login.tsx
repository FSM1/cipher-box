import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { StatusIndicator } from '../components/layout';
import { GoogleLoginButton } from '../components/auth/GoogleLoginButton';
import { EmailLoginForm } from '../components/auth/EmailLoginForm';
import { MatrixBackground } from '../components/MatrixBackground';
import { StagingBanner } from '../components/StagingBanner';
import { useHealthControllerCheck } from '../api/health/health';
import { useAuth } from '../hooks/useAuth';

/**
 * Login page with terminal aesthetic and matrix background.
 * CipherBox-branded custom login UI with Google OAuth and email OTP.
 * Replaces the old Web3Auth modal [CONNECT] button (Phase 12).
 */
export function Login() {
  const { isAuthenticated, isLoading, loginWithGoogle, loginWithEmail } = useAuth();
  const navigate = useNavigate();
  const [loginError, setLoginError] = useState<string | null>(null);

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

  // Show loading state while checking authentication
  if (isLoading) {
    return (
      <>
        <StagingBanner variant="login" />
        <div className="login-container">
          <MatrixBackground opacity={0.3} frameInterval={50} />
          <div className="loading">initializing...</div>
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
          </div>

          {loginError && (
            <div className="login-error" role="alert" aria-live="polite">
              {loginError}
            </div>
          )}
        </div>
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
      </div>
    </>
  );
}
