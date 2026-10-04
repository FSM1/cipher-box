/**
 * UI-owned auth chrome: how the session was established and what to display for
 * it. Whether the tab *has* a session is the engine's word, read through
 * `useEngineAccount` — this store has no say in it, so there is no second
 * answer to desync from the first (blueprint/web-client.md "UI state law").
 * Vault state, tokens, and key material live below the facade. Memory only —
 * `display` is PII for Google and email sign-ins, and this store is never
 * persisted.
 */

import { useSyncExternalStore } from 'react';

/** How the session was established. */
export type LoginMethod = 'google' | 'email' | 'wallet';

export type LoginFailure =
  | { readonly kind: 'error'; readonly message: string }
  | { readonly kind: 'held-elsewhere'; readonly heldBy: string | null };

export interface AuthState {
  /** What the member signed in as, for every method; a wallet's is truncated. */
  readonly display: string | null;
  readonly method: LoginMethod | null;
  /** A restore can fail in a consumer that outlives the route rendering sign-in. */
  readonly loginFailure: LoginFailure | null;
  /**
   * A login reached this account's factor policy and stopped: the tab owes a
   * recovery phrase. Held here rather than in a hook so every surface reads the
   * one answer, and a route change cannot lose the prompt over a live session.
   */
  readonly recoveryRequired: boolean;
  /**
   * This account carries a factor policy — account-wide, whatever kind of
   * factor answered it. What the approver poll runs on.
   */
  readonly factorPolicy: boolean;
  /**
   * This member holds a recovery phrase, which is one factor kind and not the
   * policy itself: a device that joined by approval holds none (ADR 0009 D2).
   * What the enrollment control runs on, so the two cannot disagree.
   */
  readonly recoveryPhraseHeld: boolean;
  /**
   * The member asked at sign-in to register this browser's device key. It
   * outlives `signedIn`, because the landing that registers reads it after the
   * flow has already published the session.
   */
  readonly saveDevice: boolean;
}

const SIGNED_OUT: AuthState = Object.freeze({
  display: null,
  method: null,
  loginFailure: null,
  recoveryRequired: false,
  factorPolicy: false,
  recoveryPhraseHeld: false,
  saveDevice: false,
});

let state: AuthState = SIGNED_OUT;
const listeners = new Set<() => void>();

function set(next: AuthState): void {
  // `useSyncExternalStore` bails out on snapshot identity, so a repeat login
  // with identical values must not mint a new object and re-render consumers.
  if (
    next.display === state.display &&
    next.method === state.method &&
    next.loginFailure === state.loginFailure &&
    next.recoveryRequired === state.recoveryRequired &&
    next.factorPolicy === state.factorPolicy &&
    next.recoveryPhraseHeld === state.recoveryPhraseHeld &&
    next.saveDevice === state.saveDevice
  ) {
    return;
  }
  // Frozen: a consumer that mutated a published snapshot would change what the
  // UI renders without notifying anyone, and React bails out on identity.
  state = Object.freeze(next);
  for (const listener of listeners) listener();
}

export const authStore = {
  subscribe(onStoreChange: () => void): () => void {
    listeners.add(onStoreChange);
    return () => listeners.delete(onStoreChange);
  },
  getState: (): AuthState => state,
  /** `method` is `null` for a session established by a means the chrome does not name. */
  signedIn(method: LoginMethod | null, display: string | null = null): void {
    set({
      display,
      method,
      loginFailure: null,
      recoveryRequired: false,
      factorPolicy: false,
      recoveryPhraseHeld: false,
      saveDevice: state.saveDevice,
    });
  },
  signedOut(): void {
    set(SIGNED_OUT);
  },
  loginFailure(failure: LoginFailure | null): void {
    set({ ...state, loginFailure: failure === null ? null : Object.freeze({ ...failure }) });
  },
  /** A login stopped at the factor policy; the front door owes a phrase. */
  recoveryRequired(): void {
    set({ ...state, recoveryRequired: true });
  },
  /** That prompt is resolved — redeemed, or abandoned. */
  recoveryResolved(): void {
    set({ ...state, recoveryRequired: false });
  },
  /**
   * What the account's factor policy reads as. Latches on for the session:
   * Web3Auth's own factor list can still answer "none" for a while after an
   * enrollment lands, and an approver poll that stopped on that answer would
   * leave a member's other device waiting. A sign-in or sign-out clears it, so
   * the next session reads the policy afresh.
   */
  factorPolicy(carries: boolean): void {
    set({ ...state, factorPolicy: state.factorPolicy || carries });
  },
  /**
   * Whether this member holds a recovery phrase. Assigned, not latched: it
   * answers for one factor kind, and only a reading of the account's own
   * factors may set it.
   */
  recoveryPhrase(held: boolean): void {
    set({ ...state, recoveryPhraseHeld: held });
  },
  saveDevice(save: boolean): void {
    set({ ...state, saveDevice: save });
  },
};

export function useAuthState(): AuthState {
  return useSyncExternalStore(authStore.subscribe, authStore.getState);
}
