import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { AppShell } from '../components/layout';
import { FileBrowser } from '../components/file-browser';
import { useAuth } from '../hooks/useAuth';

/**
 * Files page showing user's vault wrapped in AppShell.
 * Protected route - redirects to login if not authenticated.
 */
export function FilesPage() {
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
      <AppShell>
        <div className="loading">Loading...</div>
      </AppShell>
    );
  }

  // Don't render if not authenticated (redirect is in progress)
  if (!isAuthenticated) {
    return null;
  }

  return (
    <AppShell>
      <FileBrowser />
    </AppShell>
  );
}
