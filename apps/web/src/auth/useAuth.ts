/**
 * The login flow, rewired onto the facade (blueprint/web-client.md "Login and
 * identity"). CipherBox verifies the provider credential and mints the token
 * the Core Kit redeems (ADR 0008 D1); the only thing that crosses into the
 * vault is the login secret, transferred once by `handOffLoginSecret`.
 *
 * Credential collection is per-host and stays outside this hook — it takes
 * already-collected credentials and drives the sequencing.
 */

import { useCallback, useEffect, useState } from 'react';
import { handOffLoginSecret } from '../engine/loginHandoff';
import { errorMessage } from '../lib/errorMessage';
import { authStore, useAuthState } from '../stores/auth.store';
import { useEngine, useLoginSecretSource, useRebuildEngine } from '../providers/EngineProvider';
import { useCoreKit } from './CoreKitProvider';
import { useIdentity } from './IdentityProvider';
import type { CoreKitSession } from './coreKit';
import type { IdentityCredential } from './identityExchange';

export interface Auth {
  isAuthenticated: boolean;
  /** True while the tab is still assembling its engine or Core Kit session. */
  isReady: boolean;
  /**
   * True once the tab knows it has no session — the check settled signed out,
   * or Core Kit could never answer it.
   */
  isSignedOut: boolean;
  /** True while a restore, login, or logout is in flight. */
  isBusy: boolean;
  /** The last failure, already stripped of anything secret-shaped. */
  error: string | null;
  /** Exchanges a Google ID token collected on this host. */
  loginWithGoogle(idToken: string): Promise<void>;
  /** Asks CipherBox to deliver a verification code. */
  sendEmailCode(email: string): Promise<void>;
  loginWithEmailCode(email: string, code: string): Promise<void>;
  /** Issues the single-use nonce the wallet's EIP-4361 message embeds. */
  walletNonce(): Promise<string>;
  /** `signature` is the `0x`-prefixed EIP-191 hex wagmi returns, sent verbatim. */
  loginWithWallet(message: string, signature: string): Promise<void>;
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
  const { session, status, error: coreKitError } = useCoreKit();
  const { exchange } = useIdentity();
  const { isAuthenticated } = useAuthState();

  const [isBusy, setIsBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isReady = client !== null && session !== null && status === 'ready';
  const isSignedOut = !isAuthenticated && (isReady || status === 'unavailable');

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

  /**
   * One sequencing for every method: exchange the collected credential, redeem
   * it with the Core Kit, then hand the engine its secret.
   */
  const login = useCallback(
    (collect: () => Promise<IdentityCredential>) =>
      exclusively(async () => {
        if (!session) throw new Error('the login provider is not ready');
        await session.login(await collect());
        await handOff();
      }),
    [exclusively, handOff, session]
  );

  const loginWithGoogle = useCallback(
    (idToken: string) => login(() => exchange.fromGoogleToken(idToken)),
    [exchange, login]
  );

  const sendEmailCode = useCallback(
    (email: string) => exclusively(() => exchange.sendEmailCode(email)),
    [exchange, exclusively]
  );

  const loginWithEmailCode = useCallback(
    (email: string, code: string) => login(() => exchange.fromEmailCode(email, code)),
    [exchange, login]
  );

  const walletNonce = useCallback(() => exchange.walletNonce(), [exchange]);

  const loginWithWallet = useCallback(
    (message: string, signature: string) =>
      login(() => exchange.fromWalletSignature(message, signature)),
    [exchange, login]
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
    isSignedOut,
    isBusy,
    error: error ?? coreKitError,
    loginWithGoogle,
    sendEmailCode,
    loginWithEmailCode,
    walletNonce,
    loginWithWallet,
    logout,
  };
}
