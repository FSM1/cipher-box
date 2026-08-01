/**
 * The login flow, rewired onto the facade (blueprint/web-client.md "Login and
 * identity"). Core Kit authenticates the person on the UI thread; the only
 * thing that crosses into the vault is the login secret, transferred once by
 * `handOffLoginSecret`.
 */

import { useCallback, useEffect, useState } from 'react';
import { handOffLoginSecret } from '../engine/loginHandoff';
import { errorMessage } from '../lib/errorMessage';
import { authStore, useAuthState } from '../stores/auth.store';
import { useEngine, useLoginSecretSource, useRebuildEngine } from '../providers/EngineProvider';
import { useCoreKit } from './CoreKitProvider';
import type { CoreKitLoginMethod, CoreKitSession } from './coreKit';

export interface Auth {
  isAuthenticated: boolean;
  /** True while the tab is still assembling its engine or Core Kit session. */
  isReady: boolean;
  /** True while a restore, login, or logout is in flight. */
  isBusy: boolean;
  /** The last failure, already stripped of anything secret-shaped. */
  error: string | null;
  loginWithGoogle(): Promise<void>;
  loginWithEmail(email: string): Promise<void>;
  /** Issues the single-use nonce the wallet's EIP-4361 message embeds. */
  siweChallenge(): Promise<string>;
  /** Exchanges a wallet-signed SIWE message; secondary to the Core Kit methods. */
  loginWithWallet(message: string, signature: Uint8Array): Promise<void>;
  logout(): Promise<void>;
}

/**
 * There is one engine per origin and one cold start per tab, so these guards
 * are module-scoped: every `useAuth()` consumer drives the same transitions,
 * and a second one must not start a second login.
 */
let inFlight = false;
let restoredFor: CoreKitSession | null = null;

export function useAuth(): Auth {
  const client = useEngine();
  const secrets = useLoginSecretSource();
  const rebuildEngine = useRebuildEngine();
  const { session, isRestoring, error: coreKitError } = useCoreKit();
  const { isAuthenticated } = useAuthState();

  const [isBusy, setIsBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isReady = client !== null && session !== null && !isRestoring;

  /** Serializes the auth transitions; a collision rejects rather than no-ops. */
  const exclusively = useCallback(async (step: () => Promise<void>): Promise<void> => {
    if (inFlight) throw new Error('another sign-in is already in progress');
    inFlight = true;
    setIsBusy(true);
    setError(null);
    try {
      await step();
    } catch (failure) {
      setError(errorMessage(failure));
      throw failure;
    } finally {
      inFlight = false;
      setIsBusy(false);
    }
  }, []);

  /**
   * The Core Kit → engine handoff. The secret source is armed first so a
   * leadership failover mid-start can re-export it; every step after that stays
   * inside the failure envelope, so nothing can leave it armed over a UI that
   * renders signed out.
   */
  const handOff = useCallback(async (): Promise<void> => {
    if (!client || !session) throw new Error('the engine is not ready to accept a login');
    const method = session.method();
    const email = session.email();

    secrets?.use(session);
    try {
      await handOffLoginSecret(client, session);
      authStore.signedIn(method, email);
    } catch (failure) {
      secrets?.use(null);
      // A Core Kit session the engine refused is a live credential on this
      // device that nothing in the UI can reach; end it here.
      await session.logout().catch(() => undefined);
      throw failure;
    }
  }, [client, secrets, session]);

  const login = useCallback(
    (method: CoreKitLoginMethod, email?: string) =>
      exclusively(async () => {
        if (!session) throw new Error('the login provider is not ready');
        await session.login(method, email);
        await handOff();
      }),
    [exclusively, handOff, session]
  );

  const loginWithGoogle = useCallback(() => login('google'), [login]);
  const loginWithEmail = useCallback((email: string) => login('email', email), [login]);

  // Outside `exclusively`: the nonce is one step inside the wallet flow, whose
  // handoff takes the lock at `loginWithWallet`.
  const siweChallenge = useCallback(async (): Promise<string> => {
    if (!client) throw new Error('the engine is not ready to accept a login');
    return client.facade.siweChallenge();
  }, [client]);

  const loginWithWallet = useCallback(
    (message: string, signature: Uint8Array) =>
      exclusively(async () => {
        if (!client) throw new Error('the engine is not ready to accept a login');
        // Secondary method: this authenticates the account against the API, it
        // does not cold-start a vault — the engine refuses it before `start`.
        await client.facade.siweLogin(message, signature);
        authStore.signedIn('wallet');
      }),
    [client, exclusively]
  );

  const logout = useCallback(
    () =>
      exclusively(async () => {
        // Every leg runs: a refused engine zeroize must not strand the Core Kit
        // session, and a failed Core Kit logout must not leave the UI signed in.
        const outcomes = await Promise.allSettled([
          client?.facade.logout() ?? Promise.resolve(),
          session?.logout() ?? Promise.resolve(),
        ]);
        secrets?.use(null);
        restoredFor = null;
        authStore.signedOut();
        rebuildEngine();
        const failed = outcomes.find((outcome) => outcome.status === 'rejected');
        if (failed) throw failed.reason as Error;
      }),
    [client, exclusively, rebuildEngine, secrets, session]
  );

  // A Core Kit session that survived the reload still has to hand the engine its
  // secret; without this the tab renders logged-out over a live login.
  useEffect(() => {
    if (!isReady || isAuthenticated || restoredFor === session || !session?.isLoggedIn()) return;
    restoredFor = session;
    exclusively(handOff).catch(() => {
      restoredFor = null;
    });
  }, [exclusively, handOff, isAuthenticated, isReady, session]);

  return {
    isAuthenticated,
    isReady,
    isBusy,
    error: error ?? coreKitError,
    loginWithGoogle,
    loginWithEmail,
    siweChallenge,
    loginWithWallet,
    logout,
  };
}
