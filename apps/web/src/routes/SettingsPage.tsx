import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { AppShell } from '../components/layout';
import { LinkedMethods } from '../components/auth/LinkedMethods';
import { VaultExport } from '../components/vault/VaultExport';
import { useAuth } from '../hooks/useAuth';

/**
 * Settings page wrapped in AppShell.
 * Protected route - redirects to login if not authenticated.
 */
export function SettingsPage() {
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
      <div className="settings-content">
        <h2 className="settings-title">[SETTINGS]</h2>
        <section className="settings-section">
          <LinkedMethods />
        </section>
        <section className="settings-section" style={{ marginTop: 'var(--spacing-md)' }}>
          <VaultExport />
        </section>
      </div>
    </AppShell>
  );
}
