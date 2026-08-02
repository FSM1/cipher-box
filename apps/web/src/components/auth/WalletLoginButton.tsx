import { useEffect, useRef, useState } from 'react';
import { useConnect, useDisconnect, useSignMessage } from 'wagmi';
import { mainnet } from 'wagmi/chains';
import { hexToBytes } from 'viem';
import { createSiweMessage } from 'viem/siwe';
import { errorMessage } from '../../lib/errorMessage';
import { LoginError } from './LoginError';

interface WalletLoginButtonProps {
  /** Reads the single-use nonce the EIP-4361 message embeds, from the facade. */
  requestNonce: () => Promise<string>;
  /** Hands the signed EIP-4361 message to the facade. */
  onLogin: (message: string, signature: Uint8Array) => Promise<void>;
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
 * identity"): wagmi collects the wallet signature here and the facade forwards
 * it.
 */
export function WalletLoginButton({ requestNonce, onLogin, disabled }: WalletLoginButtonProps) {
  const { connectors, connectAsync } = useConnect();
  const { signMessageAsync } = useSignMessage();
  const { disconnect } = useDisconnect();

  const [phase, setPhase] = useState<Phase>('idle');
  const [error, setError] = useState<string | null>(null);
  const [picking, setPicking] = useState(false);

  const busy = phase !== 'idle';

  const trigger = useRef<HTMLButtonElement>(null);
  const picker = useRef<HTMLDivElement>(null);
  const wasPicking = useRef(false);

  // Opening the picker unmounts the trigger, so keyboard focus has to move with
  // it and come back when the picker closes.
  useEffect(() => {
    if (picking) picker.current?.querySelector('button')?.focus();
    else if (wasPicking.current) trigger.current?.focus();
    wasPicking.current = picking;
  }, [picking]);

  const signIn = async (connector: (typeof connectors)[number]) => {
    setError(null);
    // Past the handoff the facade owns the outcome, and the page renders it;
    // this component only reports what went wrong on the wallet's side of it.
    let handedOff = false;
    try {
      setPhase('connecting');
      const { accounts } = await connectAsync({ connector });
      const [account] = accounts;
      if (!account) throw new Error('the wallet returned no account');

      // The nonce first, then the phase: the label promises a wallet prompt
      // that only appears once the message exists.
      const nonce = await requestNonce();
      setPhase('signing');
      const message = createSiweMessage({
        address: account,
        chainId: mainnet.id,
        domain: window.location.host,
        nonce,
        uri: window.location.origin,
        version: '1',
        statement: 'Sign in to CipherBox encrypted storage',
      });
      // Pin the account the message names: a mid-flow account switch would
      // otherwise sign with one address over a message naming another.
      const signature = await signMessageAsync({ account, message });

      setPhase('verifying');
      handedOff = true;
      await onLogin(message, hexToBytes(signature));
      setPicking(false);
    } catch (failure) {
      if (!handedOff) setError(rejectionOf(failure));
    } finally {
      // CipherBox needs the wallet for one signature, never a standing session.
      disconnect();
      setPhase('idle');
    }
  };

  // EIP-6963 can announce the same wallet twice; one row per name.
  const unique = connectors.filter((c, i, all) => all.findIndex((x) => x.name === c.name) === i);

  return (
    <div className="wallet-login-wrapper">
      {picking ? (
        <div
          ref={picker}
          className="wallet-connector-list"
          role="group"
          aria-label="Available wallets"
        >
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
              <div className="wallet-connector-header">// select wallet</div>
              {unique.map((connector) => (
                <button
                  key={connector.uid}
                  type="button"
                  className="wallet-connector-option"
                  onClick={() => void signIn(connector)}
                  disabled={busy}
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
            // cancel
          </button>
        </div>
      ) : (
        <button
          ref={trigger}
          type="button"
          data-testid="wallet-login-button"
          className="terminal-btn"
          onClick={() => {
            setError(null);
            setPicking(true);
          }}
          disabled={disabled}
          aria-label="Sign in with wallet"
        >
          {PHASE_LABEL.idle}
        </button>
      )}
      {error && <LoginError message={error} />}
    </div>
  );
}

/** Renders a wallet refusal as a refusal rather than as a raw provider dump. */
function rejectionOf(failure: unknown): string {
  const text = errorMessage(failure);
  return /user rejected|ACTION_REJECTED/i.test(text) ? 'the wallet request was rejected' : text;
}
