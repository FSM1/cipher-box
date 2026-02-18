import { useCallback, useEffect, useRef, useState } from 'react';
import { useConnect, useAccount, useSignMessage, useDisconnect } from 'wagmi';
import { createSiweMessage } from 'viem/siwe';
import { authApi } from '../../lib/api/auth';

type WalletLoginButtonProps = {
  onLogin: (idToken: string, userId: string) => Promise<void>;
  disabled?: boolean;
};

type LoginPhase = 'idle' | 'connecting' | 'signing' | 'verifying';

/**
 * Wallet login button using wagmi for wallet connection and viem for SIWE.
 *
 * Flow:
 * 1. Show "Connect Wallet" button
 * 2. On click, show discovered EIP-6963 wallet connectors
 * 3. User selects connector, wagmi connects, gets address
 * 4. Fetch nonce from backend
 * 5. Create SIWE message with viem
 * 6. Prompt user to sign in wallet
 * 7. Send message+signature to backend for verification
 * 8. Receive CipherBox JWT and call onLogin
 * 9. Disconnect wagmi (no persistent wallet connection needed)
 */
export function WalletLoginButton({ onLogin, disabled }: WalletLoginButtonProps) {
  const { connectors, connectAsync, isPending: isConnecting } = useConnect();
  const { address, isConnected } = useAccount();
  const { signMessageAsync } = useSignMessage();
  const { disconnect } = useDisconnect();

  const [phase, setPhase] = useState<LoginPhase>('idle');
  const [error, setError] = useState<string | null>(null);
  const [showConnectors, setShowConnectors] = useState(false);

  // Track whether SIWE flow is in progress to prevent double-triggers
  const siweInProgress = useRef(false);

  // When wagmi connects and we have an address, trigger the SIWE flow
  useEffect(() => {
    if (isConnected && address && phase === 'connecting' && !siweInProgress.current) {
      siweInProgress.current = true;
      handleSiweFlow(address);
    }
  }, [isConnected, address, phase]);

  const handleSiweFlow = async (walletAddress: `0x${string}`) => {
    try {
      setPhase('signing');

      // 1. Get nonce from backend
      const { nonce } = await authApi.identityWalletNonce();

      // 2. Create SIWE message
      const message = createSiweMessage({
        address: walletAddress,
        chainId: 1,
        domain: window.location.host,
        nonce,
        uri: window.location.origin,
        version: '1',
        statement: 'Sign in to CipherBox encrypted storage',
      });

      // 3. Sign message with wallet
      const signature = await signMessageAsync({ message });

      setPhase('verifying');

      // 4. Verify on backend, get CipherBox JWT
      const { idToken, userId } = await authApi.identityWalletVerify({
        message,
        signature,
      });

      // 5. Disconnect wagmi (we don't need persistent wallet connection)
      disconnect();

      // 6. Continue with Core Kit login
      await onLogin(idToken, userId);

      // Reset state on success
      setPhase('idle');
      setShowConnectors(false);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Wallet login failed';

      // Handle user rejection specifically
      if (
        message.includes('User rejected') ||
        message.includes('user rejected') ||
        message.includes('ACTION_REJECTED')
      ) {
        setError('Signature request was rejected');
      } else {
        setError(message);
      }

      // Clean up on failure
      disconnect();
      setPhase('idle');
      setShowConnectors(false);
    } finally {
      siweInProgress.current = false;
    }
  };

  const handleConnectorClick = useCallback(
    async (connector: (typeof connectors)[0]) => {
      setError(null);
      setPhase('connecting');

      try {
        const result = await connectAsync({ connector });
        const walletAddress = result.accounts[0];

        if (!walletAddress) {
          throw new Error('No wallet address returned');
        }

        // connectAsync resolves with the address, so we can start SIWE immediately
        siweInProgress.current = true;
        await handleSiweFlow(walletAddress);
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Connection failed';

        if (
          msg.includes('User rejected') ||
          msg.includes('user rejected') ||
          msg.includes('ACTION_REJECTED')
        ) {
          setError('Wallet connection was rejected');
        } else if (msg.includes('No provider')) {
          setError('No wallet detected. Please install MetaMask or another wallet.');
        } else {
          setError(msg);
        }

        setPhase('idle');
        setShowConnectors(false);
        siweInProgress.current = false;
      }
    },
    [connectAsync, signMessageAsync, disconnect, onLogin]
  );

  const handleButtonClick = () => {
    if (phase !== 'idle') return;
    setError(null);
    setShowConnectors(true);
  };

  const handleCancel = () => {
    setShowConnectors(false);
    setError(null);
    if (isConnected) {
      disconnect();
    }
    setPhase('idle');
    siweInProgress.current = false;
  };

  const isWorking = phase !== 'idle';
  const isDisabled = disabled || isWorking;

  const buttonText = () => {
    switch (phase) {
      case 'connecting':
        return 'connecting wallet...';
      case 'signing':
        return 'sign the message in your wallet...';
      case 'verifying':
        return 'verifying signature...';
      default:
        return '[WALLET]';
    }
  };

  // Filter to unique named connectors (EIP-6963 can report duplicates)
  const uniqueConnectors = connectors.filter(
    (c, i, arr) => arr.findIndex((x) => x.name === c.name) === i
  );

  return (
    <div className="wallet-login-wrapper">
      {!showConnectors ? (
        <button
          type="button"
          data-testid="wallet-login-button"
          className={['wallet-login-btn', isWorking ? 'wallet-login-btn--loading' : '']
            .filter(Boolean)
            .join(' ')}
          onClick={handleButtonClick}
          disabled={isDisabled}
          aria-label="Sign in with wallet"
          aria-busy={isWorking}
        >
          {buttonText()}
        </button>
      ) : (
        <div className="wallet-connector-list" role="group" aria-label="Available wallets">
          {phase !== 'idle' ? (
            <div className="wallet-login-status" aria-live="polite">
              {buttonText()}
            </div>
          ) : uniqueConnectors.length === 0 ? (
            <div className="wallet-no-providers">
              no wallets detected. install MetaMask or another browser wallet.
            </div>
          ) : (
            <>
              <div className="wallet-connector-header">{'// select wallet'}</div>
              {uniqueConnectors.map((connector) => (
                <button
                  key={connector.uid}
                  type="button"
                  className="wallet-connector-option"
                  onClick={() => handleConnectorClick(connector)}
                  disabled={isConnecting || isWorking}
                  aria-label={`Connect with ${connector.name}`}
                >
                  [{connector.name}]
                </button>
              ))}
            </>
          )}
          <button
            type="button"
            className="wallet-connector-cancel"
            onClick={handleCancel}
            disabled={phase === 'verifying'}
            aria-label="Cancel wallet connection"
          >
            {'// cancel'}
          </button>
        </div>
      )}
      {error && (
        <div className="login-error" role="alert" aria-live="polite">
          {error}
        </div>
      )}
    </div>
  );
}
