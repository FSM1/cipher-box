import { useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { SignInPanel } from '../components/auth/SignInPanel';
import { MatrixBackground } from '../components/MatrixBackground';
import { StagingBanner } from '../components/StagingBanner';
import { useEngineAccount } from '../engine/useEngineSession';

/** The vault's front door. */
export function LoginPage() {
  const isAuthenticated = useEngineAccount() !== null;
  const navigate = useNavigate();
  const { pathname } = useLocation();

  // Only redirect away from the login route itself, so a late settle cannot yank
  // a user who has already navigated on.
  useEffect(() => {
    if (isAuthenticated && pathname === '/') navigate('/files');
  }, [isAuthenticated, navigate, pathname]);

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

          <SignInPanel />
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
