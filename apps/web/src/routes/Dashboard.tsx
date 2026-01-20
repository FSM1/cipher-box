import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { LogoutButton } from '../components/auth/LogoutButton';
import { useAuth } from '../hooks/useAuth';

/**
 * Dashboard page showing user's vault.
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
        <h1>CipherBox</h1>
        <div className="user-info">
          {userInfo?.email && <span className="user-email">{userInfo.email}</span>}
          <button onClick={() => navigate('/settings')} className="settings-link">
            Settings
          </button>
          <LogoutButton />
        </div>
      </header>
      <main className="dashboard-main">
        <aside className="folder-sidebar">
          <h2>Folders</h2>
          <p className="placeholder-text">Folder tree coming in Phase 5</p>
        </aside>
        <section className="file-area">
          <h2>Files</h2>
          <p className="placeholder-text">File browser coming in Phase 6</p>
        </section>
      </main>
    </div>
  );
}
