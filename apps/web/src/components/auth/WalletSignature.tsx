import { useEffect, useRef, useState } from 'react';
import { useConnect, useDisconnect, useSignMessage } from 'wagmi';
import { mainnet } from 'wagmi/chains';
import { createSiweMessage } from 'viem/siwe';
import { rejectionOf } from './walletRejection';

interface WalletSignatureProps {
  /** The EIP-4361 `statement`, which is what the member is being asked to sign. */
  statement: string;
  /** Reads the single-use nonce the message embeds. */
  requestNonce: () => Promise<string>;
  /** Takes the signed message on; past this the caller owns the outcome. */
  onSigned: (message: string, signature: string) => Promise<void>;
  /** What the trigger says, and how tests and screen readers find it. */
  trigger: { label: string; ariaLabel: string; testId: string };
  /** What the status line says once the signature is handed off. */
  handoffLabel: string;
  /** A wallet-side refusal, or `null` to retire the last one. */
  onRejected: (message: string | null) => void;
  disabled?: boolean;
}

type Phase = 'idle' | 'connecting' | 'signing' | 'handoff';

/**
 * One wallet signature, collected through wagmi: connect, sign an EIP-4361
 * message over a nonce the caller supplies, hand it off, disconnect.
 *
 * Sign-in and wallet-linking differ only in the statement, the nonce source and
 * what happens after the handoff, so both drive this rather than each carrying
 * its own connect/sign/disconnect flow.
 */
export function WalletSignature({
  statement,
  requestNonce,
  onSigned,
  trigger,
  handoffLabel,
  onRejected,
  disabled,
}: WalletSignatureProps) {
  const { connectors, connectAsync } = useConnect();
  const { signMessageAsync } = useSignMessage();
  const { disconnect } = useDisconnect();

  const [phase, setPhase] = useState<Phase>('idle');
  const [picking, setPicking] = useState(false);
  const busy = phase !== 'idle';

  const triggerRef = useRef<HTMLButtonElement>(null);
  const picker = useRef<HTMLDivElement>(null);
  const wasPicking = useRef(false);

  // Opening the picker unmounts the trigger, so keyboard focus has to move with
  // it and come back when the picker closes.
  useEffect(() => {
    if (picking) picker.current?.querySelector('button')?.focus();
    else if (wasPicking.current) triggerRef.current?.focus();
    wasPicking.current = picking;
  }, [picking]);

  const phaseLabel: Record<Phase, string> = {
    idle: trigger.label,
    connecting: 'connecting wallet...',
    signing: 'sign the message in your wallet...',
    handoff: handoffLabel,
  };

  const sign = async (connector: (typeof connectors)[number]) => {
    onRejected(null);
    // Past the handoff the caller owns the outcome and renders it; this
    // component only reports what went wrong on the wallet's side of it.
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
        statement,
      });
      // Pin the account the message names: a mid-flow account switch would
      // otherwise sign with one address over a message naming another.
      const signature = await signMessageAsync({ account, message });

      setPhase('handoff');
      handedOff = true;
      await onSigned(message, signature);
      setPicking(false);
    } catch (failure) {
      if (!handedOff) onRejected(rejectionOf(failure));
    } finally {
      // CipherBox needs the wallet for one signature, never a standing session.
      disconnect();
      setPhase('idle');
    }
  };

  if (!picking) {
    return (
      <button
        ref={triggerRef}
        type="button"
        data-testid={trigger.testId}
        className="terminal-btn"
        onClick={() => {
          onRejected(null);
          setPicking(true);
        }}
        disabled={disabled}
        aria-label={trigger.ariaLabel}
      >
        {trigger.label}
      </button>
    );
  }

  // EIP-6963 can announce the same wallet twice; one row per name.
  const unique = connectors.filter((c, i, all) => all.findIndex((x) => x.name === c.name) === i);

  return (
    <div ref={picker} className="wallet-connector-list" role="group" aria-label="Available wallets">
      {busy ? (
        <div className="wallet-login-status" aria-live="polite">
          {phaseLabel[phase]}
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
              onClick={() => void sign(connector)}
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
        disabled={phase === 'handoff'}
        aria-label="Cancel wallet connection"
      >
        // cancel
      </button>
    </div>
  );
}
