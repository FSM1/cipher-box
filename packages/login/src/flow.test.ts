import { describe, expect, it, vi } from 'vitest';
import { createLoginFlow, type LoginFlow } from './flow';
import type { LoginSecretExporter } from './secret';
import {
  fakeAccount,
  fakeExchange,
  fakeFacade,
  fakeProgress,
  fakeSession,
  FAKE_IDENTITY_TOKEN,
  FAKE_NONCE,
  passThroughCollector,
  type WebCollected,
} from './testFakes';

const SECRET_BYTES = Uint8Array.from({ length: 32 }, () => 0x0f);

type Parts = ReturnType<typeof build>;

function build(
  options: {
    offered?: { google?: boolean; email?: boolean; wallet?: boolean };
    facade?: ReturnType<typeof fakeFacade>;
    session?: ReturnType<typeof fakeSession>;
  } = {}
) {
  const exchange = fakeExchange();
  const session = options.session ?? fakeSession();
  const facade = options.facade ?? fakeFacade();
  const account = fakeAccount();
  const progress = fakeProgress();
  const armed: (LoginSecretExporter | null)[] = [];
  let rebuilds = 0;
  const flow: LoginFlow<WebCollected> = createLoginFlow<WebCollected>({
    exchange: exchange.exchange,
    collector: passThroughCollector(options.offered),
    session: session.session,
    facade: facade.facade,
    secrets: { use: (exporter) => armed.push(exporter) },
    account: account.account,
    progress: progress.progress,
    afterLogout: () => {
      rebuilds += 1;
    },
  });
  return { flow, exchange, session, facade, account, progress, armed, rebuilds: () => rebuilds };
}

const loggedIn = (parts: Parts) => parts.account.calls.signedIn;

describe('the login flow', () => {
  it('exchanges the collected google token, then hands the engine the login secret', async () => {
    const parts = build();

    await parts.flow.loginWithGoogle('google.id.token');

    expect(parts.exchange.calls.google).toEqual(['google.id.token']);
    expect(parts.session.calls.logins).toEqual([
      {
        method: 'google',
        token: FAKE_IDENTITY_TOKEN,
        verifierId: 'subject-for-google',
        email: 'user@example.test',
      },
    ]);
    expect(parts.facade.calls.secrets).toEqual([SECRET_BYTES]);
    expect(loggedIn(parts)).toEqual([{ method: 'google', email: 'user@example.test' }]);
  });

  it('asks CipherBox for the code, then redeems what the host collected', async () => {
    const parts = build();

    await parts.flow.sendEmailCode('user@example.test');
    await parts.flow.loginWithEmailCode({ email: 'user@example.test', code: '123456' });

    expect(parts.exchange.calls.sentCodes).toEqual(['user@example.test']);
    expect(parts.exchange.calls.verified).toEqual([{ email: 'user@example.test', code: '123456' }]);
    expect(parts.facade.calls.secrets).toEqual([SECRET_BYTES]);
  });

  it('carries the wallet proof to the API verbatim', async () => {
    const parts = build();
    const signature = `0x${'07'.repeat(65)}`;

    await expect(parts.flow.walletNonce()).resolves.toBe(FAKE_NONCE);
    await parts.flow.loginWithWallet({ message: 'siwe-message', signature });

    expect(parts.exchange.calls.wallet).toEqual([{ message: 'siwe-message', signature }]);
    expect(loggedIn(parts)).toEqual([{ method: 'wallet', email: null }]);
  });

  // Desktop reaches no wallet, and a build with no Google client ID renders no
  // Google button: the method is absent rather than present and unable to finish.
  it('offers only what the host collects, and refuses the rest', async () => {
    const parts = build({ offered: { google: false, email: true, wallet: false } });

    expect(parts.flow.methods).toEqual(['email']);
    expect(parts.flow.offers('wallet')).toBe(false);
    await expect(parts.flow.loginWithWallet({ message: 'm', signature: '0x00' })).rejects.toThrow(
      /wallet sign-in is not available on this device/
    );
    await expect(parts.flow.walletNonce()).rejects.toThrow(/not available/);
    await expect(parts.flow.loginWithGoogle('google.id.token')).rejects.toThrow(/not available/);

    // Refused before anything was dispatched, so no half-login is left behind.
    expect(parts.exchange.calls.nonces).toBe(0);
    expect(parts.session.calls.logins).toEqual([]);
    expect(parts.progress.seen).toEqual([]);
  });

  it('refuses a second sign-in while the first is still in flight', async () => {
    let release!: () => void;
    const facade = fakeFacade({ start: () => new Promise<void>((r) => (release = r)) });
    const parts = build({ facade });

    const first = parts.flow.loginWithGoogle('google.id.token');
    await vi.waitUntil(() => parts.facade.calls.secrets.length === 1);

    await expect(parts.flow.loginWithGoogle('google.id.token')).rejects.toThrow(
      /another sign-in is already in progress/
    );
    expect(parts.session.calls.logins).toHaveLength(1);

    release();
    await first;
  });

  it('hands the secret over for a Core Kit session that outlived the page, once', async () => {
    const parts = build({ session: fakeSession({ loggedIn: true }) });

    await parts.flow.resume();
    await parts.flow.resume();

    expect(parts.session.calls.logins).toEqual([]);
    expect(parts.facade.calls.secrets).toEqual([SECRET_BYTES]);
    // The identity token carries no email claim, so a restored session has no
    // address to show until the member signs in again.
    expect(loggedIn(parts)).toEqual([{ method: null, email: null }]);
  });

  it('disarms the re-export and ends the session when the engine refuses the secret', async () => {
    const facade = fakeFacade({ start: () => Promise.reject(new Error('trust violation')) });
    const parts = build({ facade });

    await expect(parts.flow.loginWithGoogle('google.id.token')).rejects.toThrow('trust violation');

    expect(loggedIn(parts)).toEqual([]);
    expect(parts.armed.at(-1)).toBeNull();
    expect(parts.session.calls.logouts).toBe(1);
    expect(parts.progress.failures.map(String)).toEqual(['Error: trust violation']);
  });

  it('tears both sides down on logout and still reports the failed leg', async () => {
    const facade = fakeFacade({ logout: () => Promise.reject(new Error('engine gone')) });
    const parts = build({ facade });
    await parts.flow.loginWithGoogle('google.id.token');

    await expect(parts.flow.logout()).rejects.toThrow('engine gone');

    expect(parts.session.calls.logouts).toBe(1);
    expect(parts.armed.at(-1)).toBeNull();
    expect(parts.account.signOuts()).toBe(1);
    expect(parts.rebuilds()).toBe(1);
  });
});
