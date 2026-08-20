import { useAuth } from '../auth/useAuth';
import { FileBrowser } from '../components/file-browser/FileBrowser';
import { AppShell } from '../components/layout/AppShell';

/**
 * The vault browser. `RequireAuth` has already ruled out a tab with no session;
 * what is left is one still deciding, which renders progress rather than an
 * empty vault.
 */
export function FilesPage() {
  const { isAuthenticated } = useAuth();

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
