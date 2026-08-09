import { COREKIT_STATUS } from '@web3auth/mpc-core-kit';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryKeys, sealedTestStore } from '../test/storeFakes';
import type { SealedStore } from './sealedStore';
import { createCoreKitSession, sealedCoreKitStore } from './coreKit';

const STORE_KEY = 'corekit_store';

/** What the SDK writes under its one key; nothing here is real key material. */
const SESSION = '{"sessionId":"not-a-real-session-id"}';

// The SDK reaches for the Web3Auth network on construction; the seam is what
// lets the persistence options it is handed be read back, and what drives the
// login and logout outcomes a device can actually land in.
const sdk = vi.hoisted(() => ({
  options: undefined as Record<string, unknown> | undefined,
  status: 'LOGGED_IN',
  statusAfterLogin: 'LOGGED_IN',
  logoutError: undefined as Error | undefined,
  logoutCalls: 0,
}));
vi.mock('@web3auth/mpc-core-kit', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@web3auth/mpc-core-kit')>();
  return {
    ...actual,
    Web3AuthMPCCoreKit: class {
      readonly _storageKey = STORE_KEY;
      constructor(options: Record<string, unknown>) {
        sdk.options = options;
      }
      get status(): string {
        return sdk.status;
      }
      async loginWithOAuth(): Promise<void> {
        sdk.status = sdk.statusAfterLogin;
      }
      commitChanges(): Promise<void> {
        return Promise.resolve();
      }
      logout(): Promise<void> {
        sdk.logoutCalls += 1;
        return sdk.logoutError ? Promise.reject(sdk.logoutError) : Promise.resolve();
      }
    },
  };
});

const ENV = {
  VITE_WEB3AUTH_CLIENT_ID: 'client-id',
  VITE_WEB3AUTH_VERIFIER: 'verifier',
} satisfies Partial<ImportMetaEnv>;

const REFUSED = new Error('the session server is unreachable');

describe('the Core Kit store', () => {
  let keys: MemoryKeys;
  let store: SealedStore;

  /** A session over a store this test can seed and read back. */
  const session = () => createCoreKitSession(ENV, store);

  beforeEach(() => {
    sdk.options = undefined;
    sdk.status = COREKIT_STATUS.LOGGED_IN;
    sdk.statusAfterLogin = COREKIT_STATUS.LOGGED_IN;
    sdk.logoutError = undefined;
    sdk.logoutCalls = 0;
    window.localStorage.clear();
    keys = new MemoryKeys();
    store = sealedTestStore(keys);
  });

  it('hands the SDK the sealed store, so nothing it writes lands in the clear', async () => {
    session();
    await store.setItem(STORE_KEY, SESSION);

    expect(sdk.options?.storage).toBe(store);
    expect(window.localStorage.getItem(STORE_KEY)).not.toContain('sessionId');
  });

  it('keeps the ciphertext origin-wide, so a tab that did not log in can still be promoted', async () => {
    // A store written before the seal is dropped on read, which is only
    // observable if the default store is this origin's `localStorage`.
    window.localStorage.setItem(STORE_KEY, SESSION);

    await expect(sealedCoreKitStore().getItem(STORE_KEY)).resolves.toBeNull();

    expect(window.localStorage.getItem(STORE_KEY)).toBeNull();
  });

  it('caps how long a persisted session stays restorable at eight hours', () => {
    session();

    expect(sdk.options?.sessionTime).toBe(28_800);
  });

  it('is cleared on logout, which the SDK leaves standing', async () => {
    const created = session();
    await store.setItem(STORE_KEY, SESSION);

    await created.logout();

    expect(sdk.logoutCalls).toBe(1);
    expect(window.localStorage.getItem(STORE_KEY)).toBeNull();
    expect(keys.held).toBeNull();
  });

  it('is cleared when the SDK refuses to log out, and the refusal still surfaces', async () => {
    const created = session();
    sdk.logoutError = REFUSED;
    await store.setItem(STORE_KEY, SESSION);

    await expect(created.logout()).rejects.toThrow(REFUSED);

    expect(window.localStorage.getItem(STORE_KEY)).toBeNull();
    expect(keys.held).toBeNull();
  });

  it('is cleared on a sign-out the SDK has no session to end', async () => {
    const created = session();
    sdk.status = COREKIT_STATUS.NOT_INITIALIZED;
    await store.setItem(STORE_KEY, SESSION);

    await created.logout();

    expect(sdk.logoutCalls).toBe(0);
    expect(window.localStorage.getItem(STORE_KEY)).toBeNull();
  });

  it('is cleared when a login stops short of a session and the rollback is refused', async () => {
    const created = session();
    sdk.statusAfterLogin = COREKIT_STATUS.REQUIRED_SHARE;
    sdk.logoutError = REFUSED;
    await store.setItem(STORE_KEY, SESSION);

    await expect(created.login('google')).rejects.toThrow(/needs approval or a recovery phrase/);

    expect(sdk.logoutCalls).toBe(1);
    expect(window.localStorage.getItem(STORE_KEY)).toBeNull();
  });
});
