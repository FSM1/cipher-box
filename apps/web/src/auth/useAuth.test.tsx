import { act, renderHook, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { authStore } from '../stores/auth.store';
import {
  authWrapper,
  FAKE_NONCE,
  fakeCoreKitSession,
  fakeEngineClient,
  SECRET_HEX,
} from '../test/authFakes';
import { useLoginSecretSource } from '../providers/EngineProvider';
import { useAuth } from './useAuth';

const SECRET_BYTES = Uint8Array.from({ length: 32 }, () => 0x0f);

/** Mounts `useAuth` alongside the secret source the failover path re-exports through. */
function mount(
  client: ReturnType<typeof fakeEngineClient>,
  coreKit: ReturnType<typeof fakeCoreKitSession>
) {
  return renderHook(() => ({ auth: useAuth(), secrets: useLoginSecretSource() }), {
    wrapper: authWrapper(client.client, coreKit.session),
  });
}

describe('useAuth', () => {
  beforeEach(() => authStore.signedOut());

  it('drives the Core Kit google flow and hands the engine the login secret', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession();
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    await act(() => result.current.auth.loginWithGoogle());

    expect(coreKit.calls.logins).toEqual([{ method: 'google', email: undefined }]);
    expect(engine.calls.secrets).toEqual([SECRET_BYTES]);
    expect(authStore.getState()).toMatchObject({
      isAuthenticated: true,
      method: 'google',
      email: 'user@example.test',
    });
  });

  it('passes the typed address to the Core Kit email flow before the handoff', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession();
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    await act(() => result.current.auth.loginWithEmail('user@example.test'));

    expect(coreKit.calls.logins).toEqual([{ method: 'email', email: 'user@example.test' }]);
    expect(engine.calls.secrets).toEqual([SECRET_BYTES]);
  });

  it('routes a wallet signature to the facade and exports no secret for it', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession();
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    const signature = new Uint8Array(65).fill(7);
    await act(() => result.current.auth.loginWithWallet('siwe-message', signature));

    expect(engine.calls.siwe).toEqual([{ message: 'siwe-message', signature }]);
    expect(engine.calls.started).toEqual([]);
    expect(coreKit.calls.exports).toBe(0);
    expect(authStore.getState()).toMatchObject({ isAuthenticated: true, method: 'wallet' });
  });

  it('reads the SIWE nonce from the facade, never from the API', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession();
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));

    await expect(result.current.auth.siweChallenge()).resolves.toBe(FAKE_NONCE);
    expect(engine.calls.siweChallenges).toBe(1);
  });

  it('tears down the engine and the Core Kit session on logout', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession();
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));
    await act(() => result.current.auth.loginWithGoogle());
    const secrets = result.current.secrets!;

    await act(() => result.current.auth.logout());

    expect(engine.calls.logouts).toBe(1);
    expect(coreKit.calls.logouts).toBe(1);
    expect(authStore.getState().isAuthenticated).toBe(false);
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
    expect(authStore.getState().isAuthenticated).toBe(false);
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
  });

  it('leaves the tab signed out and disarmed when the engine refuses the secret', async () => {
    const engine = fakeEngineClient({ start: () => Promise.reject(new Error('trust violation')) });
    const coreKit = fakeCoreKitSession();
    const { result } = mount(engine, coreKit);
    await waitFor(() => expect(result.current.auth.isReady).toBe(true));
    const secrets = result.current.secrets!;

    await act(async () => {
      await result.current.auth.loginWithGoogle().catch(() => undefined);
    });

    expect(authStore.getState().isAuthenticated).toBe(false);
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
      await result.current.auth.loginWithGoogle().catch(() => undefined);
    });

    expect(authStore.getState().isAuthenticated).toBe(false);
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
      first = result.current.auth.loginWithGoogle();
    });
    await waitFor(() => expect(engine.calls.started).toHaveLength(1));

    await expect(result.current.auth.loginWithGoogle()).rejects.toThrow(
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

    await act(() => result.current.auth.loginWithGoogle());

    const rendered = JSON.stringify({ auth: result.current.auth, store: authStore.getState() });
    expect(rendered).not.toContain(SECRET_HEX);
    expect(rendered).not.toContain([...SECRET_BYTES].join(','));
  });
});
