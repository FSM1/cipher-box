/**
 * UI-owned auth chrome: how the session was established and what to display for
 * it. Whether the tab *has* a session is the engine's word, read through
 * `useEngineAccount` — this store has no say in it, so there is no second
 * answer to desync from the first (blueprint/web-client.md "UI state law").
 * Vault state, tokens, and key material live below the facade. Memory only —
 * `email` is PII and this store is never persisted.
 */

import { useSyncExternalStore } from 'react';

/** How the session was established. */
export type LoginMethod = 'google' | 'email' | 'wallet';

export interface AuthState {
  /** Absent for wallet logins, which carry no email. */
  readonly email: string | null;
  readonly method: LoginMethod | null;
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
}

const SIGNED_OUT: AuthState = Object.freeze({
  email: null,
  method: null,
  recoveryRequired: false,
  factorPolicy: false,
  recoveryPhraseHeld: false,
});

let state: AuthState = SIGNED_OUT;
const listeners = new Set<() => void>();

function set(next: AuthState): void {
  // `useSyncExternalStore` bails out on snapshot identity, so a repeat login
  // with identical values must not mint a new object and re-render consumers.
  if (
    next.email === state.email &&
    next.method === state.method &&
    next.recoveryRequired === state.recoveryRequired &&
    next.factorPolicy === state.factorPolicy &&
    next.recoveryPhraseHeld === state.recoveryPhraseHeld
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
  signedIn(method: LoginMethod | null, email: string | null = null): void {
    // Drop an email a wallet login had no business carrying rather than hold
    // PII the state contract declares absent.
    set({
      email: method === 'wallet' ? null : email,
      method,
      recoveryRequired: false,
      factorPolicy: false,
      recoveryPhraseHeld: false,
    });
  },
  signedOut(): void {
    set(SIGNED_OUT);
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
};

export function useAuthState(): AuthState {
  return useSyncExternalStore(authStore.subscribe, authStore.getState);
}
