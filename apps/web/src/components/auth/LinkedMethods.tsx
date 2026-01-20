import { useState } from 'react';
import { useLinkedMethods } from '../../hooks/useLinkedMethods';
import { useAuthFlow } from '../../lib/web3auth/hooks';

const METHOD_LABELS: Record<string, string> = {
  google: 'Google',
  apple: 'Apple',
  github: 'GitHub',
  email_passwordless: 'Email',
  external_wallet: 'Wallet',
};

export function LinkedMethods() {
  const { methods, isLoading, linkMethod, unlinkMethod, isLinking, isUnlinking } =
    useLinkedMethods();
  const { connect, getIdToken, getLoginType } = useAuthFlow();
  const [linkError, setLinkError] = useState<string | null>(null);

  const handleLink = async () => {
    setLinkError(null);
    try {
      // Open Web3Auth modal to authenticate with new method
      await connect();
      const idToken = await getIdToken();
      const loginType = getLoginType();

      if (!idToken) {
        setLinkError('Failed to get authentication token');
        return;
      }

      // Link the new method
      await linkMethod({
        idToken,
        loginType,
      });
    } catch (error) {
      console.error('Failed to link method:', error);
      if (error instanceof Error) {
        // Check for publicKey mismatch error from backend
        if (error.message.includes('mismatch') || error.message.includes('Mismatch')) {
          setLinkError(
            'This auth method is linked to a different account. Both methods must derive the same key in Web3Auth.'
          );
        } else if (error.message.includes('already linked')) {
          setLinkError('This auth method is already linked to your account.');
        } else {
          setLinkError(error.message);
        }
      } else {
        setLinkError('Failed to link auth method');
      }
    }
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

      <button onClick={handleLink} disabled={isLinking} className="link-button">
        {isLinking ? 'Linking...' : 'Link Another Method'}
      </button>

      <p className="link-note">
        Note: New auth methods must derive the same cryptographic key (via Web3Auth account
        linking).
      </p>
    </div>
  );
}
