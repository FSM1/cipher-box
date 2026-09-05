import { useState } from 'react';
import { LoginError } from '@cipherbox/auth-ui';
import { WalletSignature } from './WalletSignature';

interface WalletLoginButtonProps {
  /** Reads the single-use nonce the EIP-4361 message embeds. */
  requestNonce: () => Promise<string>;
  /** Hands the signed EIP-4361 message to the login flow. */
  onLogin: (message: string, signature: string) => Promise<void>;
  disabled?: boolean;
}

/**
 * Wallet login, a first-class first login on web (ADR 0008 D2): wagmi collects
 * the signature here, and the API verifies it and mints the same identity token
 * every other method mints — so it reaches the same derived key.
 */
export function WalletLoginButton({ requestNonce, onLogin, disabled }: WalletLoginButtonProps) {
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="wallet-login-wrapper">
      <WalletSignature
        statement="Sign in to CipherBox encrypted storage"
        requestNonce={requestNonce}
        onSigned={onLogin}
        trigger={{
          label: '[WALLET]',
          ariaLabel: 'Sign in with wallet',
          testId: 'wallet-login-button',
        }}
        handoffLabel="verifying signature..."
        onRejected={setError}
        disabled={disabled}
      />
      {error && <LoginError message={error} />}
    </div>
  );
}
