/**
 * The login flow, rewired onto the facade (blueprint/web-client.md "Login and
 * identity"). Core Kit authenticates the person on the UI thread; the only
 * thing that crosses into the vault is the login secret, transferred once by
 * `handOffLoginSecret`. Nothing here derives a key, holds a token, or talks to
 * the API — `facade.start` runs the engine's own challenge-signature login.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { handOffLoginSecret } from '../engine/loginHandoff';
import { authStore, useAuthState } from '../stores/auth.store';
import { useEngine, useLoginSecretSource } from '../providers/EngineProvider';
import { useCoreKit } from './CoreKitProvider';
import type { CoreKitLoginMethod } from './coreKit';

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
  /** Exchanges a wallet-signed SIWE message; secondary to the Core Kit methods. */
  loginWithWallet(message: string, signature: Uint8Array): Promise<void>;
  logout(): Promise<void>;
}

export function useAuth(): Auth {
  const client = useEngine();
  const secrets = useLoginSecretSource();
  const { session, isRestoring, error: coreKitError } = useCoreKit();
  const { isAuthenticated } = useAuthState();

  const [isBusy, setIsBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);

  const isReady = client !== null && session !== null && !isRestoring;

  /**
   * Serializes the auth transitions: `start` is once-per-engine, and Core Kit's
   * popup flows do not survive being opened twice.
   */
  const exclusively = useCallback(async (step: () => Promise<void>): Promise<void> => {
    if (inFlight.current) return;
    inFlight.current = true;
    setIsBusy(true);
    setError(null);
    try {
      await step();
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
      throw failure;
    } finally {
      inFlight.current = false;
      setIsBusy(false);
    }
  }, []);

  /**
   * The Core Kit → engine handoff. The secret source is armed first so a
   * leadership failover mid-start can re-export it, and disarmed if the engine
   * refuses the secret.
   */
  const handOff = useCallback(async (): Promise<void> => {
    if (!client || !session) throw new Error('the engine is not ready to accept a login');
    secrets?.use(session);
    try {
      await handOffLoginSecret(client, session);
    } catch (failure) {
      secrets?.use(null);
      throw failure;
    }
    authStore.signedIn(session.method(), session.email());
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

  const loginWithWallet = useCallback(
    (message: string, signature: Uint8Array) =>
      exclusively(async () => {
        if (!client) throw new Error('the engine is not ready to accept a login');
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
        const failures = await Promise.allSettled([
          client?.facade.logout() ?? Promise.resolve(),
          session?.logout() ?? Promise.resolve(),
        ]);
        secrets?.use(null);
        authStore.signedOut();
        const failed = failures.find((outcome) => outcome.status === 'rejected');
        if (failed) throw failed.reason as Error;
      }),
    [client, exclusively, secrets, session]
  );

  // A Core Kit session that survived the reload still has to hand the engine its
  // secret; without this the tab renders logged-out over a live login.
  const restored = useRef(false);
  useEffect(() => {
    if (restored.current || !isReady || isAuthenticated || !session?.isLoggedIn()) return;
    restored.current = true;
    exclusively(handOff).catch(() => undefined);
  }, [exclusively, handOff, isAuthenticated, isReady, session]);

  return {
    isAuthenticated,
    isReady,
    isBusy: isBusy || isRestoring,
    error: error ?? coreKitError,
    loginWithGoogle,
    loginWithEmail,
    loginWithWallet,
    logout,
  };
}
