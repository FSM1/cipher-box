/**
 * React's binding to the shared login flow (ADR 0008 D3). The sequencing lives
 * in `@cipherbox/login`; this hook supplies the web host's parts — the facade
 * the client wraps, the Core Kit session, the collector, the auth chrome — and
 * renders the transitions as component state.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { createLoginFlow, type LoginProgress } from '@cipherbox/login';
import { errorMessage } from '../lib/errorMessage';
import { authStore, useAuthState } from '../stores/auth.store';
import { useEngine, useLoginSecretSource, useRebuildEngine } from '../providers/EngineProvider';
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
}

export function useAuth(): Auth {
  const client = useEngine();
  const secrets = useLoginSecretSource();
  const rebuildEngine = useRebuildEngine();
  const { session, status, error: coreKitError } = useCoreKit();
  const { exchange, collector } = useIdentity();
  const { isAuthenticated } = useAuthState();

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

  const loginWithEmailCode = useCallback(
    (email: string, code: string) => flow.loginWithEmailCode({ email, code }),
    [flow]
  );

  const loginWithWallet = useCallback(
    (message: string, signature: string) => flow.loginWithWallet({ message, signature }),
    [flow]
  );

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
    loginWithGoogle: flow.loginWithGoogle,
    sendEmailCode: flow.sendEmailCode,
    loginWithEmailCode,
    walletNonce: flow.walletNonce,
    loginWithWallet,
    logout: flow.logout,
  };
}
