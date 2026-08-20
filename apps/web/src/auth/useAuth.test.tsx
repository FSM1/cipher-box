import { EngineHeldElsewhereError } from '@cipherbox/client';
import { act, renderHook, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { authStore } from '../stores/auth.store';
import {
  authWrapper,
  FAKE_IDENTITY_TOKEN,
  FAKE_NONCE,
  FAKE_PHRASE,
  fakeCoreKitSession,
  fakeEngineClient,
  fakeIdentityExchange,
  SECRET_HEX,
} from '../test/authFakes';
import { useLoginSecretSource } from '../providers/EngineProvider';
import { useAuth } from './useAuth';

const SECRET_BYTES = Uint8Array.from({ length: 32 }, () => 0x0f);

/** Stands in for what Google Identity Services hands the page. */
const GOOGLE_ID_TOKEN = 'google.id.token';

/** Mounts `useAuth` alongside the secret source the failover path re-exports through. */
function mount(
  client: ReturnType<typeof fakeEngineClient>,
  coreKit: ReturnType<typeof fakeCoreKitSession>,
  identity: ReturnType<typeof fakeIdentityExchange> = fakeIdentityExchange()
) {
  return renderHook(() => ({ auth: useAuth(), secrets: useLoginSecretSource() }), {
    wrapper: authWrapper(client.client, coreKit.session, identity.exchange),
  });
}

describe('useAuth recovery phrase', () => {
  beforeEach(() => authStore.signedOut());

  it('prompts for the phrase rather than reporting a failure', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession({ needsRecovery: true });
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    await act(() => result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN));

    expect(result.current.auth.recoveryRequired).toBe(true);
    // The prompt is the outcome, not an error to render beside it.
    expect(result.current.auth.error).toBeNull();
    expect(engine.calls.secrets).toEqual([]);
  });

  it('hands the engine its secret once the phrase opens the account', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession({ needsRecovery: true });
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));
    await act(() => result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN));

    await act(() => result.current.auth.loginWithRecoveryPhrase(FAKE_PHRASE));

    expect(coreKit.calls.phrases).toEqual([FAKE_PHRASE]);
    expect(result.current.auth.recoveryRequired).toBe(false);
    expect(engine.calls.secrets).toEqual([SECRET_BYTES]);
    expect(result.current.auth.isAuthenticated).toBe(true);
  });

  it('keeps the prompt up for another attempt after a wrong phrase', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession({ needsRecovery: true });
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));
    await act(() => result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN));

    await act(async () => {
      await expect(result.current.auth.loginWithRecoveryPhrase('wrong')).rejects.toThrow();
    });

    expect(result.current.auth.recoveryRequired).toBe(true);
    expect(result.current.auth.error).toMatch(/does not open this account/);
    expect(coreKit.calls.logouts).toBe(0);
    expect(engine.calls.secrets).toEqual([]);
  });

  it('holds the prompt where every surface reads it, not per hook instance', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession({ needsRecovery: true });
    const { result } = mount(engine, coreKit);
    const second = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    await act(() => result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN));
    expect(second.result.current.auth.recoveryRequired).toBe(true);

    // The panel is its own consumer, so a cancel taken there has to reach the
    // page that decided to render it.
    await act(() => second.result.current.auth.cancelRecovery());
    expect(result.current.auth.recoveryRequired).toBe(false);
  });

  it('holds the enrollment answer where every surface reads it, not per hook instance', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession({ loggedIn: true });
    const { result } = mount(engine, coreKit);
    const menu = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));
    await act(() => result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN));
    expect(menu.result.current.auth.recoveryEnrolled).toBe(false);

    await act(async () => {
      await result.current.auth.enrollRecoveryPhrase();
    });

    // The menu that offers enrollment is a different consumer from the dialog
    // that performs it; one still offering it would enroll a second time.
    expect(menu.result.current.auth.recoveryEnrolled).toBe(true);
  });

  it('ends the partial session when the member abandons the prompt', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession({ needsRecovery: true });
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));
    await act(() => result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN));

    await act(() => result.current.auth.cancelRecovery());

    expect(result.current.auth.recoveryRequired).toBe(false);
    expect(coreKit.calls.logouts).toBe(1);
  });
});

describe('useAuth', () => {
  beforeEach(() => authStore.signedOut());

  it('exchanges the google credential, then hands the engine the login secret', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession();
    const identity = fakeIdentityExchange();
    const { result } = mount(engine, coreKit, identity);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    await act(() => result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN));

    expect(identity.calls.google).toEqual([GOOGLE_ID_TOKEN]);
    expect(coreKit.calls.logins).toEqual([
      {
        method: 'google',
        token: FAKE_IDENTITY_TOKEN,
        verifierId: 'subject-for-google',
        email: 'user@example.test',
      },
    ]);
    expect(engine.calls.secrets).toEqual([SECRET_BYTES]);
    // Signed in because the engine took the secret, not because the chrome said so.
    expect(result.current.auth.isAuthenticated).toBe(true);
    expect(authStore.getState()).toMatchObject({
      method: 'google',
      email: 'user@example.test',
    });
  });

  it('asks CipherBox for the code, then redeems it for the login secret', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession();
    const identity = fakeIdentityExchange();
    const { result } = mount(engine, coreKit, identity);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    await act(() => result.current.auth.sendEmailCode('user@example.test'));
    await act(() => result.current.auth.loginWithEmailCode('user@example.test', '123456'));

    expect(identity.calls.sentCodes).toEqual(['user@example.test']);
    expect(identity.calls.verified).toEqual([{ email: 'user@example.test', code: '123456' }]);
    expect(coreKit.calls.logins).toHaveLength(1);
    expect(engine.calls.secrets).toEqual([SECRET_BYTES]);
  });

  // The wallet is a first login now, not a secondary method: it lands on the
  // same mint, the same Core Kit login and the same secret handoff as Google.
  it('cold-starts a vault from a wallet signature', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession();
    const identity = fakeIdentityExchange();
    const { result } = mount(engine, coreKit, identity);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    const signature = `0x${'07'.repeat(65)}`;
    await act(() => result.current.auth.loginWithWallet('siwe-message', signature));

    expect(identity.calls.wallet).toEqual([{ message: 'siwe-message', signature }]);
    expect(coreKit.calls.logins).toHaveLength(1);
    expect(engine.calls.secrets).toEqual([SECRET_BYTES]);
    // The engine's own SIWE login is not what a first wallet login travels.
    expect(engine.calls.siwe).toEqual([]);
    expect(result.current.auth.isAuthenticated).toBe(true);
    expect(authStore.getState()).toMatchObject({ method: 'wallet' });
  });

  it('reads the SIWE nonce from the API, which the engine cannot answer pre-start', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession();
    const identity = fakeIdentityExchange();
    const { result } = mount(engine, coreKit, identity);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    await expect(result.current.auth.walletNonce()).resolves.toBe(FAKE_NONCE);
    expect(identity.calls.nonces).toBe(1);
    expect(engine.calls.siweChallenges).toBe(0);
  });

  it('tears down the engine and the Core Kit session on logout', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession();
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));
    await act(() => result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN));
    const secrets = result.current.secrets!;

    await act(() => result.current.auth.logout());

    expect(engine.calls.logouts).toBe(1);
    expect(coreKit.calls.logouts).toBe(1);
    expect(result.current.auth.isAuthenticated).toBe(false);
    // The re-export capability must not outlive the session it belonged to.
    await expect(secrets.provideSecret()).rejects.toThrow(/no login session/);
  });

  it('tears the Core Kit session down even when the engine refuses to log out', async () => {
    const engine = fakeEngineClient({ logout: () => Promise.reject(new Error('engine gone')) });
    const coreKit = fakeCoreKitSession();
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    await act(async () => {
      await result.current.auth.logout().catch(() => undefined);
    });

    expect(coreKit.calls.logouts).toBe(1);
    // The engine is zeroized whatever it answered, so the tab is signed out.
    expect(result.current.auth.isAuthenticated).toBe(false);
    expect(result.current.auth.error).toBe('engine gone');
  });

  it('replaces the closed engine client so the tab can log in again', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession();
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));
    const firstSource = result.current.secrets!;

    await act(() => result.current.auth.logout());

    // A new secret source means a new client: `facade.logout` closed the old one.
    await waitFor(() => expect(result.current.secrets).not.toBe(firstSource));
    expect(result.current.auth.isReady).toBe(true);
  });

  it('hands the secret over for a Core Kit session that survived the reload', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession({ loggedIn: true });
    const { result } = mount(engine, coreKit);

    await waitFor(() => expect(result.current.auth.isAuthenticated).toBe(true));

    expect(coreKit.calls.logins).toEqual([]);
    expect(engine.calls.secrets).toEqual([SECRET_BYTES]);
    // The identity token carries no email claim, so a session restored without
    // a fresh login has no address to show until the member signs in again.
    expect(authStore.getState()).toMatchObject({ email: null });
  });

  it('leaves the tab signed out and disarmed when the engine refuses the secret', async () => {
    const engine = fakeEngineClient({ start: () => Promise.reject(new Error('trust violation')) });
    const coreKit = fakeCoreKitSession();
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));
    const secrets = result.current.secrets!;

    await act(async () => {
      await result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN).catch(() => undefined);
    });

    expect(result.current.auth.isAuthenticated).toBe(false);
    expect(result.current.auth.error).toBe('trust violation');
    await expect(secrets.provideSecret()).rejects.toThrow(/no login session/);
    // A Core Kit session the engine refused is ended rather than left resident.
    expect(coreKit.calls.logouts).toBe(1);
    // The refused buffer is scrubbed rather than left holding the scalar.
    expect(new Uint8Array(engine.calls.started[0])).toEqual(new Uint8Array(32));
  });

  it('disarms the secret source when reading the session metadata throws', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession({
      email: () => {
        throw new Error('userNotLoggedIn');
      },
    });
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));
    const secrets = result.current.secrets!;

    await act(async () => {
      await result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN).catch(() => undefined);
    });

    expect(result.current.auth.isAuthenticated).toBe(false);
    expect(engine.calls.started).toEqual([]);
    await expect(secrets.provideSecret()).rejects.toThrow(/no login session/);
  });

  it('refuses a second sign-in while the first is still in flight', async () => {
    let release!: () => void;
    const engine = fakeEngineClient({ start: () => new Promise<void>((r) => (release = r)) });
    const coreKit = fakeCoreKitSession();
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    let first!: Promise<void>;
    act(() => {
      first = result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN);
    });
    await waitFor(() => expect(engine.calls.started).toHaveLength(1));

    await expect(result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN)).rejects.toThrow(
      /another sign-in is already in progress/
    );
    expect(coreKit.calls.logins).toHaveLength(1);

    await act(async () => {
      release();
      await first;
    });
  });

  it('keeps the login secret out of React state and the auth store', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession();
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    await act(() => result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN));

    const rendered = JSON.stringify({ auth: result.current.auth, store: authStore.getState() });
    expect(rendered).not.toContain(SECRET_HEX);
    expect(rendered).not.toContain([...SECRET_BYTES].join(','));
  });
});

describe('useAuth against an engine another account holds', () => {
  beforeEach(() => authStore.signedOut());

  it('renders the refusal as a signed-in-elsewhere state naming the holder', async () => {
    const engine = fakeEngineClient({
      start: () => Promise.reject(new EngineHeldElsewhereError('other-account')),
    });
    const coreKit = fakeCoreKitSession();
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    await act(async () => {
      await expect(result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN)).rejects.toThrow();
    });

    expect(result.current.auth.heldElsewhere).toEqual({ heldBy: 'other-account' });
    // A one-line banner cannot say what to do about it, so none is rendered.
    expect(result.current.auth.error).toBeNull();
    expect(result.current.auth.isAuthenticated).toBe(false);
    // The credential the engine refused does not outlive the refusal.
    expect(coreKit.calls.logouts).toBe(1);
  });

  it('reports a tab hosting the engine that has started none as holding no account', async () => {
    const engine = fakeEngineClient({
      start: () => Promise.reject(new EngineHeldElsewhereError(null)),
    });
    const { result } = mount(engine, fakeCoreKitSession());
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    await act(async () => {
      await expect(result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN)).rejects.toThrow();
    });

    expect(result.current.auth.heldElsewhere).toEqual({ heldBy: null });
  });

  it('clears the state when the next attempt begins', async () => {
    let refuse = true;
    const engine = fakeEngineClient({
      start: () =>
        refuse ? Promise.reject(new EngineHeldElsewhereError(null)) : Promise.resolve(),
    });
    const { result } = mount(engine, fakeCoreKitSession());
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));
    await act(async () => {
      await expect(result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN)).rejects.toThrow();
    });

    refuse = false;
    await act(() => result.current.auth.loginWithGoogle(GOOGLE_ID_TOKEN));

    expect(result.current.auth.heldElsewhere).toBeNull();
    expect(result.current.auth.isAuthenticated).toBe(true);
  });
});
