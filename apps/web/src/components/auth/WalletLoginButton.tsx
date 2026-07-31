import { useState } from 'react';
import { useConnect, useDisconnect, useSignMessage } from 'wagmi';
import { createSiweMessage } from 'viem/siwe';
import { fromHex } from '@cipherbox/client';
import { requestSiweNonce } from '../../auth/siweNonce';

interface WalletLoginButtonProps {
  /** Hands the signed EIP-4361 message to the facade. */
  onLogin: (message: string, signature: Uint8Array) => Promise<void>;
  apiBaseUrl: string;
  disabled?: boolean;
}

type Phase = 'idle' | 'connecting' | 'signing' | 'verifying';

const PHASE_LABEL: Record<Phase, string> = {
  idle: '[WALLET]',
  connecting: 'connecting wallet...',
  signing: 'sign the message in your wallet...',
  verifying: 'verifying signature...',
};

/**
 * SIWE, the secondary auth method (blueprint/web-client.md "Login and
 * identity"): wagmi collects the wallet signature here on the UI thread and the
 * facade forwards it. No key material and no token touches this component.
 */
export function WalletLoginButton({ onLogin, apiBaseUrl, disabled }: WalletLoginButtonProps) {
  const { connectors, connectAsync } = useConnect();
  const { signMessageAsync } = useSignMessage();
  const { disconnect } = useDisconnect();

  const [phase, setPhase] = useState<Phase>('idle');
  const [error, setError] = useState<string | null>(null);
  const [picking, setPicking] = useState(false);

  const signIn = async (connector: (typeof connectors)[number]) => {
    setError(null);
    // Past the handoff the facade owns the outcome, and the page renders it;
    // this component only reports what went wrong on the wallet's side of it.
    let handedOff = false;
    try {
      setPhase('connecting');
      const { accounts } = await connectAsync({ connector });

      setPhase('signing');
      const message = createSiweMessage({
        address: accounts[0],
        chainId: 1,
        domain: window.location.host,
        nonce: await requestSiweNonce(apiBaseUrl),
        uri: window.location.origin,
        version: '1',
        statement: 'Sign in to CipherBox encrypted storage',
      });
      const signature = await signMessageAsync({ message });

      setPhase('verifying');
      handedOff = true;
      await onLogin(message, fromHex(signature.slice(2)));
      setPicking(false);
    } catch (failure) {
      if (!handedOff) setError(describe(failure));
    } finally {
      // CipherBox needs the wallet for one signature, never a standing session.
      disconnect();
      setPhase('idle');
    }
  };

  const busy = phase !== 'idle';

  if (!picking) {
    return (
      <div className="wallet-login-wrapper">
        <button
          type="button"
          data-testid="wallet-login-button"
          className="wallet-login-btn"
          onClick={() => {
            setError(null);
            setPicking(true);
          }}
          disabled={disabled}
          aria-label="Sign in with wallet"
        >
          [WALLET]
        </button>
        {error && <LoginError message={error} />}
      </div>
    );
  }

  // EIP-6963 can announce the same wallet twice; one row per name.
  const unique = connectors.filter((c, i, all) => all.findIndex((x) => x.name === c.name) === i);

  return (
    <div className="wallet-login-wrapper">
      <div className="wallet-connector-list" role="group" aria-label="Available wallets">
        {busy ? (
          <div className="wallet-login-status" aria-live="polite">
            {PHASE_LABEL[phase]}
          </div>
        ) : unique.length === 0 ? (
          <div className="wallet-no-providers">
            no wallets detected. install MetaMask or another browser wallet.
          </div>
        ) : (
          <>
            <div className="wallet-connector-header">{'// select wallet'}</div>
            {unique.map((connector) => (
              <button
                key={connector.uid}
                type="button"
                className="wallet-connector-option"
                onClick={() => void signIn(connector)}
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
          onClick={() => setPicking(false)}
          disabled={phase === 'verifying'}
          aria-label="Cancel wallet connection"
        >
          {'// cancel'}
        </button>
      </div>
      {error && <LoginError message={error} />}
    </div>
  );
}

function LoginError({ message }: { message: string }) {
  return (
    <div className="login-error" role="alert" aria-live="polite">
      {message}
    </div>
  );
}

/** Renders a wallet refusal as a refusal rather than as a raw provider dump. */
function describe(failure: unknown): string {
  const text = failure instanceof Error ? failure.message : String(failure);
  return /user rejected|ACTION_REJECTED/i.test(text) ? 'the wallet request was rejected' : text;
}
