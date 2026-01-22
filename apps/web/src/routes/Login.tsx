import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ApiStatusIndicator } from '../components/ApiStatusIndicator';
import { AuthButton } from '../components/auth/AuthButton';
import { useAuth } from '../hooks/useAuth';

/**
 * Login page with landing content and Sign In button.
 * Per 02-CONTEXT.md: Landing page first with brief intro/value prop and prominent Sign In button.
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
        <div className="loading">Loading...</div>
      </div>
    );
  }

  return (
    <div className="login-container">
      <h1>CipherBox</h1>
      <p className="tagline">Zero-knowledge encrypted cloud storage</p>
      <p className="login-description">
        Your files, encrypted on your device. We never see your data.
      </p>
      <AuthButton />
      <ApiStatusIndicator />
    </div>
  );
}
