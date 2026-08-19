import { afterEach, describe, expect, it } from 'vitest';
import { authStore } from './auth.store';

afterEach(() => authStore.signedOut());

describe('auth.store', () => {
  it('starts signed out', () => {
    expect(authStore.getState()).toEqual({
      isAuthenticated: false,
      email: null,
      method: null,
      recoveryRequired: false,
      recoveryEnrolled: false,
    });
  });

  it('records the method and email a login carries, and nothing the last session left', () => {
    authStore.recoveryRequired();
    authStore.recoveryEnrollment(true);

    authStore.signedIn('google', 'user@example.com');

    // Exact: a prompt or a factor policy carried over from whoever was signed
    // in last would be read against this account.
    expect(authStore.getState()).toEqual({
      isAuthenticated: true,
      email: 'user@example.com',
      method: 'google',
      recoveryRequired: false,
      recoveryEnrolled: false,
    });
  });

  it('holds the enrollment answer on once it is known, against a stale re-read', () => {
    authStore.signedIn('google', 'user@example.com');
    authStore.recoveryEnrollment(true);

    // Web3Auth's factor list can still answer "none" for a while after an
    // enrollment lands; taking that would offer enrollment a second time.
    authStore.recoveryEnrollment(false);

    expect(authStore.getState().recoveryEnrolled).toBe(true);
  });

  it('accepts a wallet login with no email', () => {
    authStore.signedIn('wallet');
    expect(authStore.getState().email).toBeNull();
    expect(authStore.getState().isAuthenticated).toBe(true);
  });

  it('drops an email handed to a wallet login', () => {
    authStore.signedIn('wallet', 'user@example.com');
    expect(authStore.getState().email).toBeNull();
  });

  it('publishes frozen snapshots', () => {
    expect(Object.isFrozen(authStore.getState())).toBe(true);
    authStore.signedIn('google', 'user@example.com');
    expect(Object.isFrozen(authStore.getState())).toBe(true);
  });

  it('clears the session on sign-out', () => {
    authStore.signedIn('email', 'user@example.com');
    authStore.recoveryRequired();
    authStore.recoveryEnrollment(true);

    authStore.signedOut();

    expect(authStore.getState()).toEqual({
      isAuthenticated: false,
      email: null,
      method: null,
      recoveryRequired: false,
      recoveryEnrolled: false,
    });
  });

  it('notifies subscribers until they unsubscribe', () => {
    let changes = 0;
    const drop = authStore.subscribe(() => (changes += 1));

    authStore.signedIn('google', 'user@example.com');
    expect(changes).toBe(1);

    // A repeat login of identical values must not re-render consumers.
    const snapshot = authStore.getState();
    authStore.signedIn('google', 'user@example.com');
    expect(changes).toBe(1);
    expect(authStore.getState()).toBe(snapshot);

    drop();
    authStore.signedOut();
    expect(changes).toBe(1);
  });

  it('persists nothing', () => {
    localStorage.clear();
    sessionStorage.clear();
    authStore.signedIn('email', 'user@example.com');

    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
});
