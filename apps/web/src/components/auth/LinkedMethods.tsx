import { useState } from 'react';
import { useLinkedMethods } from '../../hooks/useLinkedMethods';

// TODO: Restore method linking with Core Kit auth flow (Phase 12.3 SIWE + Unified Identity)

const METHOD_LABELS: Record<string, string> = {
  google: 'Google',
  apple: 'Apple',
  github: 'GitHub',
  email: 'Email',
  wallet: 'Wallet',
};

export function LinkedMethods() {
  const { methods, isLoading, unlinkMethod, isUnlinking } = useLinkedMethods();
  const [linkError, setLinkError] = useState<string | null>(null);

  const handleLink = async () => {
    // Method linking requires Core Kit integration -- deferred to Phase 12.3
    setLinkError('Method linking is temporarily disabled during auth migration. Coming soon.');
  };

  const handleUnlink = async (methodId: string) => {
    if (methods.length <= 1) {
      alert('Cannot unlink your only auth method');
      return;
    }
    try {
      await unlinkMethod(methodId);
    } catch (error) {
      console.error('Failed to unlink method:', error);
      alert('Failed to unlink auth method');
    }
  };

  if (isLoading) {
    return (
      <div className="linked-methods">
        <h3>Linked Auth Methods</h3>
        <div className="loading">Loading...</div>
      </div>
    );
  }

  return (
    <div className="linked-methods">
      <h3>Linked Auth Methods</h3>
      <p className="methods-description">
        Link multiple sign-in methods to access your vault from any device or provider.
      </p>

      {linkError && (
        <div className="link-error" role="alert">
          {linkError}
          <button onClick={() => setLinkError(null)} className="dismiss-error">
            Dismiss
          </button>
        </div>
      )}

      <ul className="methods-list">
        {methods.map((method) => (
          <li key={method.id} className="method-item">
            <div className="method-info">
              <span className="method-type">{METHOD_LABELS[method.type] || method.type}</span>
              <span className="method-identifier">{method.identifier}</span>
            </div>
            <button
              onClick={() => handleUnlink(method.id)}
              disabled={isUnlinking || methods.length <= 1}
              className="unlink-button"
              title={
                methods.length <= 1 ? 'Cannot unlink your only auth method' : 'Unlink this method'
              }
            >
              Unlink
            </button>
          </li>
        ))}
      </ul>

      <button onClick={handleLink} className="link-button">
        Link Another Method
      </button>

      <p className="link-note">
        Note: New auth methods must derive the same cryptographic key (via account linking).
      </p>
    </div>
  );
}
