import { describe, expect, it, vi } from 'vitest';
import { createLoginFlow, type LoginFlow } from './flow';
import type { LoginSecretExporter } from './secret';
import { RecoveryRequiredError, type CoreKitSession } from './session';
import {
  fakeAccount,
  fakeExchange,
  fakeFacade,
  fakeProgress,
  fakeSession,
  FAKE_IDENTITY_TOKEN,
  FAKE_NONCE,
  FAKE_PHRASE,
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

describe('the recovery phrase step', () => {
  it('reports a login held at the factor policy as a transition, not a failure', async () => {
    const parts = build({ session: fakeSession({ needsRecovery: true }) });

    await expect(parts.flow.loginWithGoogle('google.id.token')).rejects.toBeInstanceOf(
      RecoveryRequiredError
    );

    // The host renders the phrase prompt; a banner beside it would be noise.
    expect(parts.progress.failures).toEqual([]);
    expect(parts.progress.seen).toEqual(['begin', 'end']);
    expect(parts.facade.calls.secrets).toEqual([]);
  });

  it('hands the engine its secret once the phrase opens the account', async () => {
    const parts = build({ session: fakeSession({ needsRecovery: true }) });
    await expect(parts.flow.loginWithGoogle('google.id.token')).rejects.toBeInstanceOf(
      RecoveryRequiredError
    );

    await parts.flow.recoverWithPhrase(FAKE_PHRASE);

    expect(parts.session.calls.phrases).toEqual([FAKE_PHRASE]);
    expect(parts.facade.calls.secrets).toEqual([SECRET_BYTES]);
    expect(loggedIn(parts)).toEqual([{ method: 'google', email: 'user@example.test' }]);
  });

  it('rejects rather than reporting success when the engine refuses the secret', async () => {
    // The whole point of running the handoff under the flow's own envelope: a
    // refused engine must leave the member at the prompt, not at a blank vault.
    const facade = fakeFacade({ start: () => Promise.reject(new Error('engine refused')) });
    const parts = build({ session: fakeSession({ needsRecovery: true }), facade });
    await expect(parts.flow.loginWithGoogle('google.id.token')).rejects.toBeInstanceOf(
      RecoveryRequiredError
    );

    await expect(parts.flow.recoverWithPhrase(FAKE_PHRASE)).rejects.toThrow('engine refused');

    expect(loggedIn(parts)).toEqual([]);
    expect(parts.progress.failures).toHaveLength(1);
  });

  // Desktop's session has no phrase redemption of its own, so the seam is
  // optional and the flow has to refuse rather than call through undefined.
  it('refuses a phrase on a host whose session cannot redeem one', async () => {
    const bare = fakeSession({ needsRecovery: true });
    delete (bare.session as Partial<CoreKitSession>).recoverWithPhrase;
    const parts = build({ session: bare });

    await expect(parts.flow.recoverWithPhrase(FAKE_PHRASE)).rejects.toThrow(
      'recovery is not available on this device'
    );

    expect(parts.facade.calls.secrets).toEqual([]);
  });

  it('leaves the login held when the phrase does not open the account', async () => {
    const parts = build({ session: fakeSession({ needsRecovery: true }) });
    await expect(parts.flow.loginWithGoogle('google.id.token')).rejects.toBeInstanceOf(
      RecoveryRequiredError
    );

    await expect(parts.flow.recoverWithPhrase('wrong')).rejects.toThrow('wrong phrase');

    expect(parts.session.calls.logouts).toBe(0);
    expect(parts.facade.calls.secrets).toEqual([]);
  });
});

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

  // The host rebuilds the flow whenever it replaces the engine facade, and a
  // replacement facade holds no secret however old the Core Kit session is.
  it('hands the secret to a replacement facade for an unchanged session', async () => {
    const session = fakeSession({ loggedIn: true });
    const before = build({ session });
    await before.flow.resume();

    const after = build({ session, facade: fakeFacade() });
    await after.flow.resume();

    expect(before.facade.calls.secrets).toEqual([SECRET_BYTES]);
    expect(after.facade.calls.secrets).toEqual([SECRET_BYTES]);
    expect(after.progress.failures).toEqual([]);
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

describe('forgetting this device', () => {
  it('erases each half before it tears that half down', async () => {
    const order: string[] = [];
    const facade = fakeFacade({
      forgetDevice: () => {
        order.push('erase');
        return Promise.resolve();
      },
      logout: () => {
        order.push('teardown');
        return Promise.resolve();
      },
    });
    const parts = build({ facade });
    await parts.flow.loginWithGoogle('google.id.token');

    await parts.flow.forgetDevice();

    // The seam wipe rides the transport the teardown closes.
    expect(order).toEqual(['erase', 'teardown']);
    expect(parts.session.calls.forgets).toBe(1);
    expect(parts.session.calls.logouts).toBe(1);
    expect(parts.account.signOuts()).toBe(1);
  });

  /** A logout that erased would destroy a vault nobody asked it to. */
  it('is never what a logout does', async () => {
    const parts = build();
    await parts.flow.loginWithGoogle('google.id.token');

    await parts.flow.logout();

    expect(parts.facade.calls.forgets).toBe(0);
    expect(parts.session.calls.forgets).toBe(0);
  });

  /**
   * The remote leg needs a live session and the network; the local erase is
   * what this device's safety rests on and must land without either.
   */
  it('tears the session down even when the erase refused, and still reports it', async () => {
    const facade = fakeFacade({ forgetDevice: () => Promise.reject(new Error('seam gone')) });
    const parts = build({ facade });
    await parts.flow.loginWithGoogle('google.id.token');

    await expect(parts.flow.forgetDevice()).rejects.toThrow('seam gone');

    expect(parts.facade.calls.logouts).toBe(1);
    expect(parts.session.calls.forgets).toBe(1);
    expect(parts.session.calls.logouts).toBe(1);
    expect(parts.armed.at(-1)).toBeNull();
    expect(parts.account.signOuts()).toBe(1);
  });

  /** Fail-closed: a plain logout must never pass for an erase. */
  it('refuses on a host whose facade cannot erase', async () => {
    const facade = fakeFacade();
    delete (facade.facade as Partial<typeof facade.facade>).forgetDevice;
    const parts = build({ facade });
    await parts.flow.loginWithGoogle('google.id.token');

    await expect(parts.flow.forgetDevice()).rejects.toThrow('cannot be forgotten');

    expect(parts.facade.calls.logouts).toBe(0);
    expect(parts.account.signOuts()).toBe(0);
  });
});
