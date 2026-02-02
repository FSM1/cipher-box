/**
 * @deprecated - Use FilesPage instead. Kept for reference during migration.
 * This component is no longer used in routes - /dashboard redirects to /files.
 * Can be deleted after Phase 6.3 is verified complete.
 */
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { LogoutButton } from '../components/auth/LogoutButton';
import { FileBrowser } from '../components/file-browser';
import { useAuth } from '../hooks/useAuth';

/**
 * @deprecated Dashboard page - replaced by FilesPage with AppShell.
 * Protected route - redirects to login if not authenticated.
 */
export function Dashboard() {
  const { isAuthenticated, isLoading, userInfo } = useAuth();
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
      <div className="dashboard-container">
        <div className="loading">Loading...</div>
      </div>
    );
  }

  // Don't render if not authenticated (redirect is in progress)
  if (!isAuthenticated) {
    return null;
  }

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <h1 className="app-title">&gt; CIPHERBOX</h1>
        <div className="user-info">
          {userInfo?.email && <span className="user-email">{userInfo.email.toLowerCase()}</span>}
          <button onClick={() => navigate('/settings')} className="settings-link">
            settings
          </button>
          <LogoutButton />
        </div>
      </header>
      <main className="dashboard-main">
        <FileBrowser />
      </main>
    </div>
  );
}
