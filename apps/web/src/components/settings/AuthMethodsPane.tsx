import { useState } from 'react';
import type { AuthMethodKind } from '@cipherbox/client';
import { useAuthMethods } from '../../hooks/useAuthMethods';
import { WalletSignature } from '../auth/WalletSignature';

const KIND_LABEL: Record<AuthMethodKind, string> = {
  identity: 'identity key',
  wallet: 'wallet',
  test: 'test',
  unknown: 'unrecognised',
};

/** Why the account's last remaining method cannot go, in the API's own terms. */
const ONLY_METHOD = 'an account must keep at least one login method';

/**
 * The login methods on this account: what opens it, and the one exchange that
 * adds or removes one.
 *
 * Only the display identifier the API serves reaches this pane — never a
 * plaintext address and never the identifier hash — so nothing here can put one
 * in the DOM.
 */
export function AuthMethodsPane() {
  const { methods, busy, error, challenge, link, unlink } = useAuthMethods();
  const [walletError, setWalletError] = useState<string | null>(null);

  const lastOne = methods.length <= 1;
  const message = walletError ?? error;

  return (
    <section className="settings-section" data-testid="settings-auth-methods">
      <h3>login methods</h3>
      <p className="sharing-note">
        {'// every method here opens this account. the account keeps at least one.'}
      </p>

      <ul className="settings-methods">
        {methods.map((method) => (
          <li key={method.id} className="settings-method">
            <span className="settings-method-kind">{KIND_LABEL[method.kind]}</span>
            <span className="settings-method-id">{method.identifierDisplay ?? '—'}</span>
            <span className="settings-method-used">
              {method.lastUsedAt === null ? 'never used' : `last used ${method.lastUsedAt}`}
            </span>
            <button
              type="button"
              className="terminal-btn terminal-btn--danger"
              onClick={() => unlink(method.id)}
              disabled={lastOne || busy}
              // A disabled control fires no hover, so the reason has to reach a
              // screen reader by name as well as by tooltip.
              title={lastOne ? ONLY_METHOD : undefined}
              aria-label={lastOne ? `unlink — ${ONLY_METHOD}` : `unlink ${KIND_LABEL[method.kind]}`}
              data-testid="settings-unlink"
            >
              unlink
            </button>
          </li>
        ))}
      </ul>

      <div className="settings-actions">
        <WalletSignature
          statement="Link wallet to CipherBox account"
          requestNonce={challenge}
          onSigned={link}
          trigger={{
            label: 'link a wallet',
            ariaLabel: 'Link a wallet',
            testId: 'settings-link-wallet',
          }}
          handoffLabel="linking..."
          onRejected={setWalletError}
          disabled={busy}
        />
      </div>

      {message !== null && (
        <p className="dialog-error" role="alert" data-testid="settings-auth-error">
          {message}
        </p>
      )}
    </section>
  );
}
