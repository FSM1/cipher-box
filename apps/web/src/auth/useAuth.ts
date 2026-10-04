/**
 * React's binding to the shared login flow (ADR 0008 D3). The sequencing lives
 * in `@cipherbox/login`; this hook supplies the web host's parts — the facade
 * the client wraps, the Core Kit session, the collector, the auth chrome. A
 * login or restore failure lives in `authStore`, so it outlives the route that
 * rendered the attempt.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { EngineHeldElsewhereError } from '@cipherbox/client';
import {
  createLoginFlow,
  RecoveryRequiredError,
  type LoginFlow,
  type LoginProgress,
} from '@cipherbox/login';
import { errorMessage } from '../lib/errorMessage';
import { useEngineAccount } from '../engine/useEngineSession';
import { authStore, useAuthState, type LoginFailure } from '../stores/auth.store';
import { notificationStore } from '../stores/notification.store';
import { useEngine, useLoginSecretSource, useRebuildEngine } from '../providers/EngineProvider';
import type { RecoveryEnrollment } from './coreKit';
import { useCoreKit } from './CoreKitProvider';
import { useIdentity } from './IdentityProvider';
import { DeviceKeyUnusableError } from './deviceIdentity';
import { isAuthRefusal, registerThisDevice, SIGN_IN_TO_SAVE } from './registerThisDevice';
import type { WebCollected } from './webCollector';

const NOT_SAVED = 'this browser was not saved as a device.';

/**
 * The notice for a registration that failed at a sign-in. Only a spent or
 * expired token needs a fresh sign-in; after any other failure the token stays
 * and the settings pane can still register.
 */
function notSaved(failure: unknown): string {
  if (failure instanceof DeviceKeyUnusableError) return failure.message;
  const cause = errorMessage(failure);
  return isAuthRefusal(failure)
    ? `${NOT_SAVED} ${SIGN_IN_TO_SAVE}. ${cause}`
    : `${NOT_SAVED} ${cause}`;
}

/** The origin's engine belongs to another account; `heldBy` names it. */
export type HeldElsewhere = Extract<LoginFailure, { kind: 'held-elsewhere' }>;

export interface Auth {
  isAuthenticated: boolean;
  /** True while the tab is still assembling its engine or Core Kit session. */
  isReady: boolean;
  /**
   * True once the tab knows it has no session — the check settled signed out,
   * Core Kit could never answer it, or the engine gave the session up. Routes
   * that need a vault redirect on this.
   */
  isSignedOut: boolean;
  /** True while a restore, login, or logout is in flight. */
  isBusy: boolean;
  /** The last failure, already stripped of anything secret-shaped. */
  error: string | null;
  /** Set when this tab was refused rather than served another account's vault. */
  heldElsewhere: HeldElsewhere | null;
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
  /** Forget this device ({@link LoginFlow.forgetDevice}). */
  forgetDevice(): Promise<void>;
  /** True while a login is held at a factor policy this device has no factor for. */
  recoveryRequired: boolean;
  /** Finishes such a login from the phrase alone (ADR 0009 D2). */
  loginWithRecoveryPhrase(phrase: string): Promise<void>;
  /** Finishes it from the factor another device sealed back instead. */
  completeDeviceApproval(factorKey: Uint8Array): Promise<void>;
  /** Abandons it instead, ending the partial session on this device. */
  cancelRecovery(): Promise<void>;
  /** Whether this member holds a recovery phrase, which gates enrollment. */
  recoveryPhraseHeld: boolean;
  /** Turns the policy on; the phrase it returns is shown exactly once. */
  enrollRecoveryPhrase(): Promise<RecoveryEnrollment>;
}

export function useAuth(): Auth {
  const client = useEngine();
  const secrets = useLoginSecretSource();
  const rebuildEngine = useRebuildEngine();
  const { session, status, error: coreKitError } = useCoreKit();
  const { exchange, collector } = useIdentity();
  const { recoveryRequired, recoveryPhraseHeld, loginFailure } = useAuthState();
  // The engine's word, not this tab's: a logout in another tab zeroizes the one
  // engine the origin has, and a UI reading its own store would keep rendering
  // a vault over it.
  const isAuthenticated = useEngineAccount() !== null;

  const [isBusy, setIsBusy] = useState(false);
  // *Which* handoff has settled, not merely that one has: `flow.resume` latches
  // on the session and the facade together, so a replacement of either owes the
  // engine a fresh attempt that consumers must await in turn.
  const [resumedFlow, setResumedFlow] = useState<LoginFlow<WebCollected> | null>(null);
  // Local to the surface that enrolls: a closed dialog must not leave its
  // failure for the next consumer to render.
  const [enrollError, setEnrollError] = useState<string | null>(null);

  const isReady = client !== null && session !== null && status === 'ready';

  const progress = useMemo<LoginProgress>(
    () => ({
      begin: () => {
        setIsBusy(true);
        setEnrollError(null);
        authStore.loginFailure(null);
      },
      // A refusal by account is a state the front door renders in full, not a
      // one-line failure: its message alone cannot say what to do about it.
      failed: (failure) => {
        if (failure instanceof EngineHeldElsewhereError) {
          authStore.loginFailure({ kind: 'held-elsewhere', heldBy: failure.heldBy });
          return;
        }
        authStore.loginFailure({ kind: 'error', message: errorMessage(failure) });
      },
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
        now: () => new Date(),
        // `facade.logout` closes the client for good, so the tab needs a new one.
        afterLogout: rebuildEngine,
        // The origin's engine and session are shared across its tabs, so ending
        // one here ends it in all of them (`EngineClient.endOriginSession`).
        endsSessionElsewhere: () => client?.endOriginSession(),
      }),
    [client, collector, exchange, progress, rebuildEngine, secrets, session]
  );

  // A Core Kit session that outlived the page still owes the engine its secret,
  // so the tab has not decided yet; a guard reading that as signed out would
  // throw the member out of their own vault. It ends whether or not the handoff
  // worked — a failed one leaves no vault to guard.
  const resuming = isReady && resumedFlow !== flow && (session?.isLoggedIn() ?? false);
  const isSignedOut = !isAuthenticated && !resuming && (isReady || status === 'unavailable');

  /**
   * The account's own factor list, which the SDK answers from the factors the
   * account carries. The two readings are separate on purpose: a member who
   * joined by device approval carries a policy and holds no phrase.
   *
   * Read after each sign-in as well as on a session change, because a landed
   * sign-in clears the chrome's answers (`authStore.signedIn`) and would
   * otherwise take a reading made moments before it with them.
   */
  const readFactors = useCallback(() => {
    authStore.recoveryPhrase(session?.hasRecoveryPhrase() ?? false);
    authStore.factorPolicy(session?.hasFactorPolicy() ?? false);
  }, [session]);

  /**
   * Registers this browser when the member asked to at sign-in, while the
   * identity token of that sign-in is still fresh. The login has landed either
   * way, so a refusal is a notice and never a failed login.
   */
  const saveDeviceIfAsked = useCallback(async (): Promise<void> => {
    if (!authStore.getState().saveDevice) return;
    authStore.saveDevice(false);
    try {
      if (!session || !client) throw new Error('the engine is not ready');
      await registerThisDevice(session, client.facade);
    } catch (failure) {
      notificationStore.warn('save-device', notSaved(failure));
    }
  }, [client, session]);

  /** The recovery prompt is a transition, not a failure the host renders. */
  const attempt = useCallback(
    async (login: Promise<void>): Promise<void> => {
      try {
        await login;
      } catch (failure) {
        if (!(failure instanceof RecoveryRequiredError)) {
          // A shared browser must not hand the choice to whoever signs in next.
          authStore.saveDevice(false);
          throw failure;
        }
        authStore.recoveryRequired();
        return;
      }
      readFactors();
      await saveDeviceIfAsked();
    },
    [readFactors, saveDeviceIfAsked]
  );

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
      // A phrase that opened the account is proof of the policy it answered,
      // and proof that this member holds the phrase.
      authStore.factorPolicy(true);
      authStore.recoveryPhrase(true);
      await saveDeviceIfAsked();
    },
    [flow, saveDeviceIfAsked]
  );

  const completeDeviceApproval = useCallback(
    async (factorKey: Uint8Array): Promise<void> => {
      await flow.completeDeviceApproval(factorKey);
      // An approval answers the same factor policy a phrase would, and it hands
      // this device no phrase: the enrollment control stays on offer (D2).
      authStore.factorPolicy(true);
      await saveDeviceIfAsked();
    },
    [flow, saveDeviceIfAsked]
  );

  const cancelRecovery = useCallback(async (): Promise<void> => {
    authStore.recoveryResolved();
    await flow.logout();
  }, [flow]);

  const enrollRecoveryPhrase = useCallback(async (): Promise<RecoveryEnrollment> => {
    if (!session) throw new Error('the login provider is not ready');
    setIsBusy(true);
    setEnrollError(null);
    try {
      const enrolled = await session.enrollRecoveryPhrase();
      authStore.factorPolicy(true);
      authStore.recoveryPhrase(true);
      return enrolled;
    } catch (failure) {
      setEnrollError(errorMessage(failure));
      throw failure;
    } finally {
      setIsBusy(false);
    }
  }, [session]);

  // Once a session settles, not per render: the SDK answers by reading the
  // account's factor list.
  useEffect(() => {
    if (isAuthenticated) readFactors();
  }, [isAuthenticated, readFactors]);

  // A Core Kit session that survived the reload still has to hand the engine its
  // secret; without this the tab renders logged-out over a live login.
  useEffect(() => {
    if (!isReady || isAuthenticated) return;
    let live = true;
    void flow.resume().finally(() => {
      if (!live) return;
      readFactors();
      setResumedFlow(flow);
    });
    return () => {
      live = false;
    };
  }, [flow, isAuthenticated, isReady, readFactors]);

  return {
    isAuthenticated,
    isReady,
    isSignedOut,
    isBusy,
    error: enrollError ?? (loginFailure?.kind === 'error' ? loginFailure.message : coreKitError),
    heldElsewhere: loginFailure?.kind === 'held-elsewhere' ? loginFailure : null,
    loginWithGoogle,
    sendEmailCode: flow.sendEmailCode,
    loginWithEmailCode,
    walletNonce: flow.walletNonce,
    loginWithWallet,
    logout: flow.logout,
    forgetDevice: flow.forgetDevice,
    recoveryRequired,
    loginWithRecoveryPhrase,
    completeDeviceApproval,
    cancelRecovery,
    recoveryPhraseHeld,
    enrollRecoveryPhrase,
  };
}
