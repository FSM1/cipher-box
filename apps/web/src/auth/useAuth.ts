/**
 * React's binding to the shared login flow (ADR 0008 D3). The sequencing lives
 * in `@cipherbox/login`; this hook supplies the web host's parts — the facade
 * the client wraps, the Core Kit session, the collector, the auth chrome — and
 * renders the transitions as component state.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { createLoginFlow, RecoveryRequiredError, type LoginProgress } from '@cipherbox/login';
import { errorMessage } from '../lib/errorMessage';
import { authStore, useAuthState } from '../stores/auth.store';
import { useEngine, useLoginSecretSource, useRebuildEngine } from '../providers/EngineProvider';
import type { RecoveryEnrollment } from './coreKit';
import { useCoreKit } from './CoreKitProvider';
import { useIdentity } from './IdentityProvider';
import type { WebCollected } from './webCollector';

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
  /** True while a login is held at a factor policy this device has no factor for. */
  recoveryRequired: boolean;
  /** Finishes such a login from the phrase alone (ADR 0009 D2). */
  loginWithRecoveryPhrase(phrase: string): Promise<void>;
  /** Abandons it instead, ending the partial session on this device. */
  cancelRecovery(): Promise<void>;
  /** Whether the signed-in account already carries a factor policy. */
  recoveryEnrolled: boolean;
  /** Turns the policy on; the phrase it returns is shown exactly once. */
  enrollRecoveryPhrase(): Promise<RecoveryEnrollment>;
}

export function useAuth(): Auth {
  const client = useEngine();
  const secrets = useLoginSecretSource();
  const rebuildEngine = useRebuildEngine();
  const { session, status, error: coreKitError } = useCoreKit();
  const { exchange, collector } = useIdentity();
  const { isAuthenticated, recoveryRequired, recoveryEnrolled } = useAuthState();

  const [isBusy, setIsBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isReady = client !== null && session !== null && status === 'ready';
  const isSignedOut = !isAuthenticated && (isReady || status === 'unavailable');

  const progress = useMemo<LoginProgress>(
    () => ({
      begin: () => {
        setIsBusy(true);
        setError(null);
      },
      failed: (failure) => setError(errorMessage(failure)),
      end: () => setIsBusy(false),
    }),
    []
  );

  const flow = useMemo(
    () =>
      createLoginFlow<WebCollected>({
        exchange,
        collector,
        session,
        facade: client?.facade ?? null,
        secrets: secrets ?? null,
        account: authStore,
        progress,
        // `facade.logout` closes the client for good, so the tab needs a new one.
        afterLogout: rebuildEngine,
      }),
    [client, collector, exchange, progress, rebuildEngine, secrets, session]
  );

  /** The recovery prompt is a transition, not a failure the host renders. */
  const attempt = useCallback(async (login: Promise<void>): Promise<void> => {
    try {
      await login;
    } catch (failure) {
      if (!(failure instanceof RecoveryRequiredError)) throw failure;
      authStore.recoveryRequired();
    }
  }, []);

  const loginWithGoogle = useCallback(
    (idToken: string) => attempt(flow.loginWithGoogle(idToken)),
    [attempt, flow]
  );

  const loginWithEmailCode = useCallback(
    (email: string, code: string) => attempt(flow.loginWithEmailCode({ email, code })),
    [attempt, flow]
  );

  const loginWithWallet = useCallback(
    (message: string, signature: string) => attempt(flow.loginWithWallet({ message, signature })),
    [attempt, flow]
  );

  const loginWithRecoveryPhrase = useCallback(
    async (phrase: string): Promise<void> => {
      await flow.recoverWithPhrase(phrase);
      // A phrase that opened the account is proof of the policy it answered.
      authStore.recoveryEnrollment(true);
    },
    [flow]
  );

  const cancelRecovery = useCallback(async (): Promise<void> => {
    authStore.recoveryResolved();
    await flow.logout();
  }, [flow]);

  const enrollRecoveryPhrase = useCallback(async (): Promise<RecoveryEnrollment> => {
    if (!session) throw new Error('the login provider is not ready');
    setIsBusy(true);
    setError(null);
    try {
      const enrolled = await session.enrollRecoveryPhrase();
      authStore.recoveryEnrollment(true);
      return enrolled;
    } catch (failure) {
      setError(errorMessage(failure));
      throw failure;
    } finally {
      setIsBusy(false);
    }
  }, [session]);

  // The policy is read once a session settles, not per render: the SDK answers
  // it by decompressing the account's public key.
  useEffect(() => {
    authStore.recoveryEnrollment(isAuthenticated && (session?.hasRecoveryPhrase() ?? false));
  }, [isAuthenticated, session]);

  // A Core Kit session that survived the reload still has to hand the engine its
  // secret; without this the tab renders logged-out over a live login.
  useEffect(() => {
    if (!isReady || isAuthenticated) return;
    void flow.resume();
  }, [flow, isAuthenticated, isReady]);

  return {
    isAuthenticated,
    isReady,
    isSignedOut,
    isBusy,
    error: error ?? coreKitError,
    loginWithGoogle,
    sendEmailCode: flow.sendEmailCode,
    loginWithEmailCode,
    walletNonce: flow.walletNonce,
    loginWithWallet,
    logout: flow.logout,
    recoveryRequired,
    loginWithRecoveryPhrase,
    cancelRecovery,
    recoveryEnrolled,
    enrollRecoveryPhrase,
  };
}
