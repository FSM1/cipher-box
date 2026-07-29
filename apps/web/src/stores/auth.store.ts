/**
 * UI-owned auth chrome: who is signed in and how. Vault state never lives here
 * (blueprint/web-client.md "UI state law" — that is the snapshot adapter's job),
 * and neither do tokens or key material: the engine owns the token lifecycle,
 * and the login secret goes straight to it. Memory only — `email` is PII and
 * this store is never persisted.
 */

import { useSyncExternalStore } from 'react';

/** How the session was established (the v1 auth-method labels). */
export type LoginMethod = 'google' | 'email' | 'wallet';

export interface AuthState {
  isAuthenticated: boolean;
  /** Absent for wallet logins, which carry no email. */
  email: string | null;
  method: LoginMethod | null;
}

const SIGNED_OUT: AuthState = { isAuthenticated: false, email: null, method: null };

let state: AuthState = SIGNED_OUT;
const listeners = new Set<() => void>();

function set(next: AuthState): void {
  state = next;
  for (const listener of listeners) listener();
}

export const authStore = {
  subscribe(onStoreChange: () => void): () => void {
    listeners.add(onStoreChange);
    return () => listeners.delete(onStoreChange);
  },
  getState: (): AuthState => state,
  signedIn(method: LoginMethod, email: string | null = null): void {
    set({ isAuthenticated: true, email, method });
  },
  signedOut(): void {
    set(SIGNED_OUT);
  },
};

export function useAuthState(): AuthState {
  return useSyncExternalStore(authStore.subscribe, authStore.getState);
}
