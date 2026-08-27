import { act, fireEvent, render, screen } from '@testing-library/react';
import type { AuthMethodDescriptor } from '@cipherbox/client';
import { describe, expect, it, vi } from 'vitest';
import { AuthMethodsPane } from './AuthMethodsPane';
import { fakeCoreKitSession, fakeEngineClient, pageWrapper } from '../../test/authFakes';

// There is no wallet harness anywhere in this repo, so the pane's wallet seams
// are the mock boundary: wagmi is host key custody, not engine crypto.
const disconnect = vi.fn();
/** A checksummed address, because `createSiweMessage` validates the one it names. */
const ACCOUNT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const connectAsync = vi.fn(() => Promise.resolve({ accounts: [ACCOUNT] }));
const signMessageAsync = vi.fn(() => Promise.resolve(`0x${'ab'.repeat(65)}`));

vi.mock('wagmi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('wagmi')>()),
  useConnect: () => ({
    // EIP-6963 announces the same wallet twice; the pane must list it once.
    connectors: [
      { uid: '1', name: 'MetaMask' },
      { uid: '2', name: 'MetaMask' },
    ],
    connectAsync,
  }),
  useSignMessage: () => ({ signMessageAsync }),
  useDisconnect: () => ({ disconnect }),
}));

const IDENTITY: AuthMethodDescriptor = {
  id: 'method-identity',
  kind: 'identity',
  identifierDisplay: null,
  createdAt: '2026-08-01T10:00:00.000Z',
  lastUsedAt: null,
};

const WALLET: AuthMethodDescriptor = {
  id: 'method-wallet',
  kind: 'wallet',
  identifierDisplay: '0x1234…abcd',
  createdAt: '2026-08-02T10:00:00.000Z',
  lastUsedAt: '2026-08-27T11:00:00.000Z',
};

const TEST_METHOD: AuthMethodDescriptor = {
  id: 'method-test',
  kind: 'test',
  identifierDisplay: 'acct01',
  createdAt: '2026-08-03T10:00:00.000Z',
  lastUsedAt: null,
};

async function renderPane(methods: AuthMethodDescriptor[]) {
  const engine = fakeEngineClient({ authMethods: () => Promise.resolve(methods) });
  const Providers = pageWrapper(engine.client, fakeCoreKitSession({ loggedIn: true }).session);
  await act(async () => {
    render(
      <Providers>
        <AuthMethodsPane />
      </Providers>
    );
  });
  return engine;
}

const unlinks = () => screen.getAllByTestId('settings-unlink') as HTMLButtonElement[];

describe('the login methods pane', () => {
  it('lists each method in the display form the API serves', async () => {
    await renderPane([IDENTITY, WALLET]);

    const pane = screen.getByTestId('settings-auth-methods');
    expect(pane.textContent).toContain('0x1234…abcd');
    expect(unlinks()).toHaveLength(2);
  });

  it('refuses to unlink the account’s only method, and says why', async () => {
    const engine = await renderPane([IDENTITY]);
    const [only] = unlinks();

    expect(only.disabled).toBe(true);
    // Both, because a disabled control fires no hover and reaches no title.
    expect(only.title).toMatch(/at least one login method/);
    expect(only.getAttribute('aria-label')).toMatch(/at least one login method/);

    fireEvent.click(only);
    expect(engine.calls.unlinked).toEqual([]);
  });

  it('refuses to unlink a login the account authorises off itself, and says why', async () => {
    const engine = await renderPane([IDENTITY, TEST_METHOD, WALLET]);
    const [identity, test] = unlinks();

    for (const button of [identity, test]) {
      expect(button.disabled).toBe(true);
      expect(button.title).toMatch(/revoke nothing/);
      expect(button.getAttribute('aria-label')).toMatch(/revoke nothing/);
    }

    fireEvent.click(identity);
    fireEvent.click(test);
    expect(engine.calls.unlinked).toEqual([]);
  });

  it('unlinks the method the member picked, by id', async () => {
    const engine = await renderPane([IDENTITY, WALLET]);

    await act(async () => void fireEvent.click(unlinks()[1]));

    expect(engine.calls.unlinked).toEqual(['method-wallet']);
  });

  it('links a wallet with one signature, then lets the wallet go', async () => {
    const engine = await renderPane([IDENTITY]);

    await act(async () => void fireEvent.click(screen.getByTestId('settings-link-wallet')));
    const wallets = screen.getAllByRole('button', { name: /connect with metamask/i });
    expect(wallets).toHaveLength(1);

    await act(async () => void fireEvent.click(wallets[0]!));

    expect(engine.calls.siweChallenges).toBe(1);
    expect(engine.calls.siweLinks).toHaveLength(1);
    expect(engine.calls.siweLinks[0]!.message).toContain('Link wallet to CipherBox account');
    // CipherBox needs the wallet for one signature, never a standing session.
    expect(disconnect).toHaveBeenCalled();
  });

  it('links nothing with a signature the member cancelled before giving', async () => {
    // The wallet answers only after the cancel, which is the whole race: a
    // signature that lands late must not link a wallet the member declined.
    let release: (signature: string) => void = () => {};
    signMessageAsync.mockReturnValueOnce(
      new Promise<string>((resolve) => {
        release = resolve;
      })
    );
    const engine = await renderPane([IDENTITY]);

    await act(async () => void fireEvent.click(screen.getByTestId('settings-link-wallet')));
    await act(async () => {
      fireEvent.click(screen.getAllByRole('button', { name: /connect with metamask/i })[0]!);
    });
    fireEvent.click(screen.getByRole('button', { name: /cancel wallet connection/i }));
    await act(async () => release(`0x${'ab'.repeat(65)}`));

    expect(engine.calls.siweLinks).toEqual([]);
  });

  it('reads a last-used stamp as a date rather than as the wire string', async () => {
    await renderPane([IDENTITY, WALLET]);

    const pane = screen.getByTestId('settings-auth-methods');
    expect(pane.textContent).not.toContain(WALLET.lastUsedAt);
    expect(pane.textContent).toContain('never used');
  });
});
