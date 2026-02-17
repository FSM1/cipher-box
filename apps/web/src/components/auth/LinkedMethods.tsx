import { useCallback, useState } from 'react';
import { useConnect, useSignMessage, useDisconnect } from 'wagmi';
import { createSiweMessage } from 'viem/siwe';
import { useLinkedMethods } from '../../hooks/useLinkedMethods';
import { GoogleLoginButton } from './GoogleLoginButton';
import { EmailLoginForm } from './EmailLoginForm';
import { authApi, AuthMethod } from '../../lib/api/auth';

type LinkingType = 'google' | 'email' | 'wallet' | null;

const METHOD_LABELS: Record<string, string> = {
  google: 'Google',
  email: 'Email',
  wallet: 'Wallet',
};

const METHOD_ICONS: Record<string, string> = {
  google: 'G',
  email: '@',
  wallet: 'W',
};

/**
 * Full auth method management UI for the Settings page.
 *
 * Displays all linked auth methods with type labels and identifiers.
 * Users can link new methods (Google, email, wallet) with ownership verification,
 * and unlink methods (blocked if only one remains).
 *
 * Wallet addresses display as truncated checksummed format (e.g. 0xAbCd...1234).
 */
export function LinkedMethods() {
  const {
    methods,
    isLoading,
    linkMethod,
    unlinkMethod,
    isLinking,
    isUnlinking,
    linkError: mutationLinkError,
    resetLinkError,
  } = useLinkedMethods();

  const [linkingType, setLinkingType] = useState<LinkingType>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [unlinkingId, setUnlinkingId] = useState<string | null>(null);

  // Wallet connection via wagmi (for linking wallets)
  const { connectors, connectAsync } = useConnect();
  const { signMessageAsync } = useSignMessage();
  const { disconnect } = useDisconnect();

  const isLastMethod = methods.length <= 1;

  // Derive which method types are not yet linked (for showing "Link" buttons)
  const linkedTypes = new Set(methods.map((m: AuthMethod) => m.type));
  const availableMethods: Array<'google' | 'email' | 'wallet'> = [];
  if (!linkedTypes.has('google')) availableMethods.push('google');
  if (!linkedTypes.has('email')) availableMethods.push('email');
  // Multiple wallets allowed -- wallet is always available
  availableMethods.push('wallet');

  const clearLinking = useCallback(() => {
    setLinkingType(null);
    setActionError(null);
  }, []);

  const handleLinkGoogle = useCallback(
    async (googleIdToken: string) => {
      setActionError(null);
      try {
        // Get CipherBox identity JWT from Google token (link intent skips user creation)
        const identity = await authApi.identityGoogle(googleIdToken, 'link');
        // Link with the CipherBox JWT
        await linkMethod({
          idToken: identity.idToken,
          loginType: 'google',
        });
        clearLinking();
      } catch (err) {
        const message = extractErrorMessage(err, 'Failed to link Google account');
        setActionError(message);
      }
    },
    [linkMethod, clearLinking]
  );

  const handleLinkEmail = useCallback(
    async (email: string, otp: string) => {
      setActionError(null);
      try {
        // Verify OTP and get CipherBox identity JWT (link intent skips user creation)
        const identity = await authApi.identityEmailVerify(email, otp, 'link');
        // Link with the CipherBox JWT
        await linkMethod({
          idToken: identity.idToken,
          loginType: 'email',
        });
        clearLinking();
      } catch (err) {
        const message = extractErrorMessage(err, 'Failed to link email');
        setActionError(message);
      }
    },
    [linkMethod, clearLinking]
  );

  const handleLinkWallet = useCallback(
    async (connector: (typeof connectors)[0]) => {
      setActionError(null);
      try {
        // 1. Connect wallet
        const result = await connectAsync({ connector });
        const walletAddress = result.accounts[0];
        if (!walletAddress) {
          throw new Error('No wallet address returned');
        }

        // 2. Get nonce from backend
        const { nonce } = await authApi.identityWalletNonce();

        // 3. Create SIWE message
        const message = createSiweMessage({
          address: walletAddress,
          chainId: 1,
          domain: window.location.host,
          nonce,
          uri: window.location.origin,
          version: '1',
          statement: 'Link wallet to CipherBox account',
        });

        // 4. Sign message
        const signature = await signMessageAsync({ message });

        // 5. Link via backend (backend verifies SIWE, no identity JWT needed for wallet)
        await linkMethod({
          idToken: '', // Not used for wallet linking
          loginType: 'wallet',
          walletAddress,
          siweMessage: message,
          siweSignature: signature,
        });

        // 6. Disconnect wagmi (no persistent wallet connection needed)
        disconnect();
        clearLinking();
      } catch (err) {
        disconnect();
        const msg = err instanceof Error ? err.message : 'Failed to link wallet';
        if (msg.includes('User rejected') || msg.includes('ACTION_REJECTED')) {
          setActionError('Wallet signature was rejected');
        } else {
          setActionError(extractErrorMessage(err, 'Failed to link wallet'));
        }
      }
    },
    [connectAsync, signMessageAsync, disconnect, linkMethod, clearLinking]
  );

  const handleUnlink = useCallback(
    async (methodId: string) => {
      if (isLastMethod) return;
      setActionError(null);
      setUnlinkingId(methodId);
      try {
        await unlinkMethod(methodId);
      } catch (err) {
        setActionError(extractErrorMessage(err, 'Failed to unlink auth method'));
      } finally {
        setUnlinkingId(null);
      }
    },
    [unlinkMethod, isLastMethod]
  );

  // Filter to unique named connectors (EIP-6963 can report duplicates)
  const uniqueConnectors = connectors.filter(
    (c, i, arr) => arr.findIndex((x) => x.name === c.name) === i
  );

  if (isLoading) {
    return (
      <div className="linked-methods">
        <h3 className="linked-methods-title">{'// linked auth methods'}</h3>
        <div className="linked-methods-loading">loading methods...</div>
      </div>
    );
  }

  const displayError = actionError || (mutationLinkError ? mutationLinkError.message : null);

  return (
    <div className="linked-methods">
      <h3 className="linked-methods-title">{'// linked auth methods'}</h3>
      <p className="linked-methods-description">
        link multiple sign-in methods to access your vault from any device or provider.
      </p>

      {/* Error display */}
      {displayError && (
        <div className="linked-methods-error" role="alert" aria-live="polite">
          {displayError}
          <button
            type="button"
            onClick={() => {
              setActionError(null);
              resetLinkError();
            }}
            className="linked-methods-error-dismiss"
            aria-label="Dismiss error"
          >
            [x]
          </button>
        </div>
      )}

      {/* Linked methods list */}
      <ul className="linked-methods-list" aria-label="Linked authentication methods">
        {methods.map((method: AuthMethod) => (
          <li key={method.id} className="linked-methods-item">
            <div className="linked-methods-item-info">
              <span className="linked-methods-item-icon" aria-hidden="true">
                {METHOD_ICONS[method.type] || '?'}
              </span>
              <div className="linked-methods-item-details">
                <span className="linked-methods-item-type">
                  {METHOD_LABELS[method.type] || method.type}
                </span>
                <span className="linked-methods-item-identifier">{method.identifier}</span>
              </div>
            </div>
            <div className="linked-methods-item-actions">
              <span className="linked-methods-badge">linked</span>
              <button
                type="button"
                onClick={() => handleUnlink(method.id)}
                disabled={isLastMethod || isUnlinking}
                className="linked-methods-unlink-btn"
                title={
                  isLastMethod ? 'Cannot unlink your only auth method' : 'Unlink this auth method'
                }
                aria-label={
                  isLastMethod
                    ? `Cannot unlink ${METHOD_LABELS[method.type] || method.type} - last method`
                    : `Unlink ${METHOD_LABELS[method.type] || method.type}`
                }
              >
                {unlinkingId === method.id ? 'unlinking...' : '[unlink]'}
              </button>
              {isLastMethod && (
                <span className="linked-methods-unlink-hint">{'// last method'}</span>
              )}
            </div>
          </li>
        ))}
      </ul>

      {/* Available methods to link */}
      {!linkingType && availableMethods.length > 0 && (
        <div className="linked-methods-available">
          <h4 className="linked-methods-available-title">{'// add auth method'}</h4>
          <div className="linked-methods-available-list">
            {availableMethods.map((type) => (
              <button
                key={type}
                type="button"
                onClick={() => {
                  setActionError(null);
                  setLinkingType(type);
                }}
                disabled={isLinking}
                className="linked-methods-link-btn"
                aria-label={`Link ${METHOD_LABELS[type]} account`}
              >
                <span className="linked-methods-link-icon" aria-hidden="true">
                  {METHOD_ICONS[type]}
                </span>
                {`[link ${METHOD_LABELS[type].toLowerCase()}]`}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Link flow: Google */}
      {linkingType === 'google' && (
        <div className="linked-methods-link-flow">
          <div className="linked-methods-link-header">
            <span>{'// link google account'}</span>
            <button
              type="button"
              onClick={clearLinking}
              className="linked-methods-link-cancel"
              aria-label="Cancel linking"
            >
              [cancel]
            </button>
          </div>
          <p className="linked-methods-link-hint">
            sign in with the google account you want to link.
          </p>
          <GoogleLoginButton onLogin={handleLinkGoogle} disabled={isLinking} />
        </div>
      )}

      {/* Link flow: Email */}
      {linkingType === 'email' && (
        <div className="linked-methods-link-flow">
          <div className="linked-methods-link-header">
            <span>{'// link email'}</span>
            <button
              type="button"
              onClick={clearLinking}
              className="linked-methods-link-cancel"
              aria-label="Cancel linking"
            >
              [cancel]
            </button>
          </div>
          <p className="linked-methods-link-hint">
            enter the email address you want to link and verify with OTP.
          </p>
          <EmailLoginForm onLogin={handleLinkEmail} disabled={isLinking} />
        </div>
      )}

      {/* Link flow: Wallet */}
      {linkingType === 'wallet' && (
        <div className="linked-methods-link-flow">
          <div className="linked-methods-link-header">
            <span>{'// link wallet'}</span>
            <button
              type="button"
              onClick={() => {
                disconnect();
                clearLinking();
              }}
              className="linked-methods-link-cancel"
              aria-label="Cancel linking"
            >
              [cancel]
            </button>
          </div>
          <p className="linked-methods-link-hint">
            connect and sign with the wallet you want to link.
          </p>
          <div className="linked-methods-wallet-connectors">
            {uniqueConnectors.length === 0 ? (
              <div className="linked-methods-wallet-no-providers">
                no wallets detected. install MetaMask or another browser wallet.
              </div>
            ) : (
              uniqueConnectors.map((connector) => (
                <button
                  key={connector.uid}
                  type="button"
                  className="linked-methods-wallet-option"
                  onClick={() => handleLinkWallet(connector)}
                  disabled={isLinking}
                  aria-label={`Connect with ${connector.name}`}
                >
                  [{connector.name}]
                </button>
              ))
            )}
          </div>
        </div>
      )}

      {/* Re-verification note */}
      <p className="linked-methods-note">
        {'// '}linking requires re-verification of the new auth method to prove ownership.
      </p>
    </div>
  );
}

/**
 * Extract a user-friendly error message from an API error response.
 */
function extractErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof Error) {
    // Axios-style error with response data
    const axiosErr = err as { response?: { data?: { message?: string } } };
    if (axiosErr.response?.data?.message) {
      return axiosErr.response.data.message;
    }
    return err.message;
  }
  return fallback;
}
