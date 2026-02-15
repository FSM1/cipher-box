import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { LinkedMethods } from '../components/auth/LinkedMethods';
import { SecurityTab } from '../components/mfa/SecurityTab';
import { useAuth } from '../hooks/useAuth';

type SettingsTabId = 'linked-methods' | 'security';

/**
 * Settings page for managing account preferences.
 * Protected route - redirects to login if not authenticated.
 *
 * Tabs: Linked Methods | Security
 */
export function Settings() {
  const { isAuthenticated, isLoading } = useAuth();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<SettingsTabId>('linked-methods');

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
        <section className="settings-section" aria-labelledby="settings-account-heading">
          <h2 id="settings-account-heading" className="settings-section-heading">
            {'// account & security'}
          </h2>
          <p className="settings-section-description">
            manage your authentication methods and account security.
          </p>

          {/* Tab navigation */}
          <div className="settings-tabs" role="tablist" aria-label="Settings sections">
            <button
              type="button"
              role="tab"
              id="tab-linked-methods"
              aria-selected={activeTab === 'linked-methods'}
              aria-controls="panel-linked-methods"
              className={`settings-tab ${activeTab === 'linked-methods' ? 'active' : ''}`}
              onClick={() => setActiveTab('linked-methods')}
            >
              LINKED METHODS
            </button>
            <button
              type="button"
              role="tab"
              id="tab-security"
              aria-selected={activeTab === 'security'}
              aria-controls="panel-security"
              className={`settings-tab ${activeTab === 'security' ? 'active' : ''}`}
              onClick={() => setActiveTab('security')}
            >
              SECURITY
            </button>
          </div>

          {/* Tab panels */}
          <div
            role="tabpanel"
            id="panel-linked-methods"
            aria-labelledby="tab-linked-methods"
            hidden={activeTab !== 'linked-methods'}
          >
            {activeTab === 'linked-methods' && <LinkedMethods />}
          </div>

          <div
            role="tabpanel"
            id="panel-security"
            aria-labelledby="tab-security"
            hidden={activeTab !== 'security'}
          >
            {activeTab === 'security' && <SecurityTab />}
          </div>
        </section>
      </main>
    </div>
  );
}
