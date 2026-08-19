/**
 * UI-owned auth chrome: who is signed in and how. Vault state, tokens, and key
 * material live below the facade (blueprint/web-client.md "UI state law").
 * Memory only — `email` is PII and this store is never persisted.
 */

import { useSyncExternalStore } from 'react';

/** How the session was established. */
export type LoginMethod = 'google' | 'email' | 'wallet';

export interface AuthState {
  readonly isAuthenticated: boolean;
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
   * This account carries a factor policy. Shared for the same reason, and one
   * more: the menu that offers enrollment and the dialog that performs it are
   * separate consumers, and a menu still offering it would enroll twice.
   */
  readonly recoveryEnrolled: boolean;
}

const SIGNED_OUT: AuthState = Object.freeze({
  isAuthenticated: false,
  email: null,
  method: null,
  recoveryRequired: false,
  recoveryEnrolled: false,
});

let state: AuthState = SIGNED_OUT;
const listeners = new Set<() => void>();

function set(next: AuthState): void {
  // `useSyncExternalStore` bails out on snapshot identity, so a repeat login
  // with identical values must not mint a new object and re-render consumers.
  if (
    next.isAuthenticated === state.isAuthenticated &&
    next.email === state.email &&
    next.method === state.method &&
    next.recoveryRequired === state.recoveryRequired &&
    next.recoveryEnrolled === state.recoveryEnrolled
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
      isAuthenticated: true,
      email: method === 'wallet' ? null : email,
      method,
      recoveryRequired: false,
      recoveryEnrolled: false,
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
   * enrollment lands, and taking that answer would offer enrollment again on an
   * account that is already enrolled. A sign-in or sign-out clears it, so the
   * next session reads the policy afresh.
   */
  recoveryEnrollment(enrolled: boolean): void {
    set({ ...state, recoveryEnrolled: state.recoveryEnrolled || enrolled });
  },
};

export function useAuthState(): AuthState {
  return useSyncExternalStore(authStore.subscribe, authStore.getState);
}
