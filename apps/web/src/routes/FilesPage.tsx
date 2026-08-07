import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/useAuth';
import { FileBrowser } from '../components/file-browser/FileBrowser';
import { AppShell } from '../components/layout/AppShell';

/**
 * The vault browser. No route guard framework: an unauthenticated tab redirects
 * on facade auth state (blueprint/web-client.md "Composition").
 */
export function FilesPage() {
  const { isAuthenticated, isSignedOut } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isSignedOut) navigate('/');
  }, [isSignedOut, navigate]);

  return (
    <AppShell>
      {isAuthenticated ? (
        <FileBrowser />
      ) : (
        <p className="file-browser-loading" data-testid="files-signing-in">
          {'// CHECKING SESSION...'}
        </p>
      )}
    </AppShell>
  );
}
