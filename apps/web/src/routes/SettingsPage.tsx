import { type KeyboardEvent, useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { bytesToHex } from '@cipherbox/crypto';
import { AppShell } from '../components/layout';
import { LinkedMethods } from '../components/auth/LinkedMethods';
import { SecurityTab } from '../components/mfa/SecurityTab';
import { StorageTab } from '../components/settings/StorageTab';
import { VaultTab } from '../components/settings/VaultTab';
import { VaultExport } from '../components/vault/VaultExport';
import { useAuth } from '../hooks/useAuth';
import { useAuthStore } from '../stores/auth.store';
import { useMfaStore } from '../stores/mfa.store';

type SettingsTabId = 'linked-methods' | 'security' | 'storage' | 'vault';

const TAB_IDS: SettingsTabId[] = ['linked-methods', 'security', 'storage', 'vault'];

function handleTabKeyDown(
  e: KeyboardEvent,
  activeTab: SettingsTabId,
  setActiveTab: (id: SettingsTabId) => void
) {
  const idx = TAB_IDS.indexOf(activeTab);
  let newIdx: number | null = null;
  if (e.key === 'ArrowRight') newIdx = (idx + 1) % TAB_IDS.length;
  else if (e.key === 'ArrowLeft') newIdx = (idx - 1 + TAB_IDS.length) % TAB_IDS.length;
  else if (e.key === 'Home') newIdx = 0;
  else if (e.key === 'End') newIdx = TAB_IDS.length - 1;
  if (newIdx !== null) {
    e.preventDefault();
    setActiveTab(TAB_IDS[newIdx]);
    document.getElementById(`tab-${TAB_IDS[newIdx]}`)?.focus();
  }
}

/**
 * Settings page wrapped in AppShell.
 * Protected route - redirects to login if not authenticated.
 *
 * Tabs: Linked Methods | Security | Storage
 * VaultExport shown below tabs (always visible).
 */
export function SettingsPage() {
  const { isAuthenticated, isLoading } = useAuth();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<SettingsTabId>('linked-methods');
  const [copied, setCopied] = useState(false);
  const copyTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const vaultKeypair = useAuthStore((s) => s.vaultKeypair);

  const publicKeyHex = vaultKeypair?.publicKey ? `0x${bytesToHex(vaultKeypair.publicKey)}` : null;

  const handleCopyPublicKey = useCallback(() => {
    if (!publicKeyHex) return;
    navigator.clipboard.writeText(publicKeyHex).then(() => {
      setCopied(true);
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
      copyTimeoutRef.current = setTimeout(() => setCopied(false), 2000);
    });
  }, [publicKeyHex]);

  // Clean up timeout on unmount
  useEffect(() => {
    return () => {
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
    };
  }, []);

  // Redirect if not authenticated.
  // Skip during MFA enrollment — enableMFA() makes long Devnet calls that can
  // outlive the access token, causing a background 401 → refresh failure → logout.
  // The enrollment wizard must remain mounted to complete.
  const isEnrolling = useMfaStore((s) => s.isEnrolling);
  useEffect(() => {
    if (!isLoading && !isAuthenticated && !isEnrolling) {
      navigate('/');
    }
  }, [isAuthenticated, isLoading, isEnrolling, navigate]);

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

        <section className="settings-section" aria-labelledby="settings-account-heading">
          <h3 id="settings-account-heading" className="settings-section-heading">
            {'// account & security'}
          </h3>
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
              tabIndex={activeTab === 'linked-methods' ? 0 : -1}
              className={`settings-tab ${activeTab === 'linked-methods' ? 'active' : ''}`}
              onClick={() => setActiveTab('linked-methods')}
              onKeyDown={(e) => handleTabKeyDown(e, activeTab, setActiveTab)}
            >
              LINKED METHODS
            </button>
            <button
              type="button"
              role="tab"
              id="tab-security"
              aria-selected={activeTab === 'security'}
              aria-controls="panel-security"
              tabIndex={activeTab === 'security' ? 0 : -1}
              className={`settings-tab ${activeTab === 'security' ? 'active' : ''}`}
              onClick={() => setActiveTab('security')}
              onKeyDown={(e) => handleTabKeyDown(e, activeTab, setActiveTab)}
            >
              SECURITY
            </button>
            <button
              type="button"
              role="tab"
              id="tab-storage"
              aria-selected={activeTab === 'storage'}
              aria-controls="panel-storage"
              tabIndex={activeTab === 'storage' ? 0 : -1}
              className={`settings-tab ${activeTab === 'storage' ? 'active' : ''}`}
              onClick={() => setActiveTab('storage')}
              onKeyDown={(e) => handleTabKeyDown(e, activeTab, setActiveTab)}
            >
              STORAGE
            </button>
            <button
              type="button"
              role="tab"
              id="tab-vault"
              aria-selected={activeTab === 'vault'}
              aria-controls="panel-vault"
              tabIndex={activeTab === 'vault' ? 0 : -1}
              className={`settings-tab ${activeTab === 'vault' ? 'active' : ''}`}
              onClick={() => setActiveTab('vault')}
              onKeyDown={(e) => handleTabKeyDown(e, activeTab, setActiveTab)}
            >
              VAULT
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

          <div
            role="tabpanel"
            id="panel-storage"
            aria-labelledby="tab-storage"
            hidden={activeTab !== 'storage'}
          >
            {activeTab === 'storage' && <StorageTab />}
          </div>

          <div
            role="tabpanel"
            id="panel-vault"
            aria-labelledby="tab-vault"
            hidden={activeTab !== 'vault'}
          >
            {activeTab === 'vault' && <VaultTab />}
          </div>
        </section>

        <section className="settings-section" style={{ marginTop: 'var(--spacing-md)' }}>
          <VaultExport />
        </section>

        {publicKeyHex && (
          <section className="settings-section" style={{ marginTop: 'var(--spacing-md)' }}>
            <h3 className="settings-section-heading">{'// your public key'}</h3>
            <p className="settings-section-description">
              {'// share this key with others to receive shared files'}
            </p>
            <div className="settings-pubkey-box">
              <code className="settings-pubkey-value">{publicKeyHex}</code>
            </div>
            <button type="button" className="settings-pubkey-copy" onClick={handleCopyPublicKey}>
              {copied ? '--copied' : '--copy'}
            </button>
          </section>
        )}
      </div>
    </AppShell>
  );
}
