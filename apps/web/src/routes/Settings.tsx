import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { LinkedMethods } from '../components/auth/LinkedMethods';
import { useAuth } from '../hooks/useAuth';

/**
 * Settings page for managing account preferences.
 * Protected route - redirects to login if not authenticated.
 */
export function Settings() {
  const { isAuthenticated, isLoading } = useAuth();
  const navigate = useNavigate();

  // Redirect if not authenticated
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      navigate('/');
    }
  }, [isAuthenticated, isLoading, navigate]);

  // Show loading state while checking authentication
  if (isLoading) {
    return (
      <div className="settings-container">
        <div className="loading">Loading...</div>
      </div>
    );
  }

  // Don't render if not authenticated (redirect is in progress)
  if (!isAuthenticated) {
    return null;
  }

  return (
    <div className="settings-container">
      <header className="settings-header">
        <h1>Settings</h1>
        <button onClick={() => navigate('/files')} className="back-button">
          Back to Files
        </button>
      </header>
      <main className="settings-main">
        <section className="settings-section">
          <LinkedMethods />
        </section>
      </main>
    </div>
  );
}
