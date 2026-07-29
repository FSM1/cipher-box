import { afterEach, describe, expect, it } from 'vitest';
import { authStore } from './auth.store';

afterEach(() => authStore.signedOut());

describe('auth.store', () => {
  it('starts signed out', () => {
    expect(authStore.getState()).toEqual({
      isAuthenticated: false,
      email: null,
      method: null,
    });
  });

  it('records the method and email a login carries', () => {
    authStore.signedIn('google', 'user@example.com');
    expect(authStore.getState()).toEqual({
      isAuthenticated: true,
      email: 'user@example.com',
      method: 'google',
    });
  });

  it('accepts a wallet login with no email', () => {
    authStore.signedIn('wallet');
    expect(authStore.getState().email).toBeNull();
    expect(authStore.getState().isAuthenticated).toBe(true);
  });

  it('clears the session on sign-out', () => {
    authStore.signedIn('email', 'user@example.com');
    authStore.signedOut();
    expect(authStore.getState()).toEqual({
      isAuthenticated: false,
      email: null,
      method: null,
    });
  });

  it('notifies subscribers until they unsubscribe', () => {
    let changes = 0;
    const drop = authStore.subscribe(() => (changes += 1));

    authStore.signedIn('google', 'user@example.com');
    expect(changes).toBe(1);

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
