import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { StatusIndicator } from '../components/layout';
import { AuthButton } from '../components/auth/AuthButton';
import { MatrixBackground } from '../components/MatrixBackground';
import { StagingBanner } from '../components/StagingBanner';
import { useHealthControllerCheck } from '../api/health/health';
import { useAuth } from '../hooks/useAuth';

/**
 * Login page with terminal aesthetic and matrix background.
 * Per design: > CIPHERBOX branding, [CONNECT] button, green-on-black theme.
 */
export function Login() {
  const { isAuthenticated, isLoading } = useAuth();
  const navigate = useNavigate();

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
          <AuthButton apiDown={isApiDown} />
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
