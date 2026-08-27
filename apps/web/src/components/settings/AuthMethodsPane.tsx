import { useCallback, useEffect, useState } from 'react';
import { useConnect, useDisconnect, useSignMessage } from 'wagmi';
import { mainnet } from 'wagmi/chains';
import { createSiweMessage } from 'viem/siwe';
import type { AuthMethodDescriptor, AuthMethodKind, EngineFacade } from '@cipherbox/client';
import { fromHex } from '@cipherbox/client';
import { useCommandRunner } from '../../hooks/useCommandRunner';
import { rejectionOf } from '../auth/walletRejection';

type Command = 'authMethods' | 'siweLink' | 'unlinkAuthMethod';

type Phase = 'idle' | 'connecting' | 'signing' | 'linking';

const PHASE_LABEL: Record<Phase, string> = {
  idle: 'link a wallet',
  connecting: 'connecting wallet...',
  signing: 'sign the message in your wallet...',
  linking: 'linking...',
};

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
  const [methods, setMethods] = useState<AuthMethodDescriptor[]>([]);
  const [phase, setPhase] = useState<Phase>('idle');
  const [picking, setPicking] = useState(false);
  const [walletError, setWalletError] = useState<string | null>(null);
  const { busy, error, run } = useCommandRunner<Command>();

  const { connectors, connectAsync } = useConnect();
  const { signMessageAsync } = useSignMessage();
  const { disconnect } = useDisconnect();

  const read = useCallback(
    async (facade: EngineFacade) => setMethods(await facade.authMethods()),
    []
  );

  const reload = useCallback(() => run('authMethods', read), [run, read]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const unlink = (methodId: string) =>
    void run('unlinkAuthMethod', async (facade) => {
      await facade.unlinkAuthMethod(methodId);
      await read(facade);
    });

  const link = async (connector: (typeof connectors)[number]) => {
    setWalletError(null);
    try {
      setPhase('connecting');
      const { accounts } = await connectAsync({ connector });
      const [account] = accounts;
      if (!account) throw new Error('the wallet returned no account');

      let nonce = '';
      await run('siweLink', async (facade) => {
        nonce = await facade.siweChallenge();
      });
      if (nonce === '') return;

      setPhase('signing');
      // Pin the account the message names: a mid-flow account switch would
      // otherwise sign with one address over a message naming another.
      const message = createSiweMessage({
        address: account,
        chainId: mainnet.id,
        domain: window.location.host,
        nonce,
        uri: window.location.origin,
        version: '1',
        statement: 'Link wallet to CipherBox account',
      });
      const signature = await signMessageAsync({ account, message });

      setPhase('linking');
      // The wallet hands back `0x`-prefixed hex; the engine takes the bytes and
      // owns every re-encoding of them below the facade.
      const bytes = fromHex(signature.startsWith('0x') ? signature.slice(2) : signature);
      await run('siweLink', async (facade) => {
        await facade.siweLink(message, bytes);
        await read(facade);
      });
      setPicking(false);
    } catch (failure) {
      setWalletError(rejectionOf(failure));
    } finally {
      // CipherBox needs the wallet for one signature, never a standing session.
      disconnect();
      setPhase('idle');
    }
  };

  // EIP-6963 can announce the same wallet twice; one row per name.
  const unique = connectors.filter((c, i, all) => all.findIndex((x) => x.name === c.name) === i);
  const lastOne = methods.length <= 1;
  const working = phase !== 'idle' || busy !== null;
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
              disabled={lastOne || working}
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

      {picking ? (
        <div className="wallet-connector-list" role="group" aria-label="Available wallets">
          {working ? (
            <div className="wallet-login-status" aria-live="polite">
              {PHASE_LABEL[phase]}
            </div>
          ) : unique.length === 0 ? (
            <div className="wallet-no-providers">
              no wallets detected. install MetaMask or another browser wallet.
            </div>
          ) : (
            unique.map((connector) => (
              <button
                key={connector.uid}
                type="button"
                className="wallet-connector-option"
                onClick={() => void link(connector)}
                aria-label={`Connect with ${connector.name}`}
              >
                [{connector.name}]
              </button>
            ))
          )}
          <button
            type="button"
            className="wallet-connector-cancel"
            onClick={() => setPicking(false)}
            disabled={working}
            aria-label="Cancel wallet connection"
          >
            // cancel
          </button>
        </div>
      ) : (
        <div className="settings-actions">
          <button
            type="button"
            className="terminal-btn"
            onClick={() => {
              setWalletError(null);
              setPicking(true);
            }}
            data-testid="settings-link-wallet"
          >
            {PHASE_LABEL.idle}
          </button>
        </div>
      )}

      {message !== null && (
        <p className="dialog-error" role="alert" data-testid="settings-auth-error">
          {message}
        </p>
      )}
    </section>
  );
}
