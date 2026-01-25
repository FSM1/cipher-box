import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ApiStatusIndicator } from '../components/ApiStatusIndicator';
import { AuthButton } from '../components/auth/AuthButton';
import { MatrixBackground } from '../components/MatrixBackground';
import { useAuth } from '../hooks/useAuth';

/**
 * Login page with terminal aesthetic and matrix background.
 * Per design: > CIPHERBOX branding, [CONNECT] button, green-on-black theme.
 */
export function Login() {
  const { isAuthenticated, isLoading } = useAuth();
  const navigate = useNavigate();

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard');
    }
  }, [isAuthenticated, navigate]);

  // Show loading state while checking authentication
  if (isLoading) {
    return (
      <div className="login-container">
        <MatrixBackground />
        <div className="loading">initializing...</div>
      </div>
    );
  }

  return (
    <div className="login-container">
      <MatrixBackground />
      <h1>CIPHERBOX</h1>
      <p className="tagline">zero-knowledge encrypted storage</p>
      <p className="login-description">
        your files, encrypted on your device. we never see your data.
      </p>
      <AuthButton />
      <ApiStatusIndicator />
    </div>
  );
}
