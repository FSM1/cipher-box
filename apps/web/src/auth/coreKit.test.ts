import { COREKIT_STATUS } from '@web3auth/mpc-core-kit';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createCoreKitSession } from './coreKit';

const STORE_KEY = 'corekit_store';

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
  beforeEach(() => {
    sdk.options = undefined;
    sdk.status = COREKIT_STATUS.LOGGED_IN;
    sdk.statusAfterLogin = COREKIT_STATUS.LOGGED_IN;
    sdk.logoutError = undefined;
    sdk.logoutCalls = 0;
    window.localStorage.clear();
  });

  it('persists origin-wide, so a tab that did not log in can still be promoted to leader', () => {
    createCoreKitSession(ENV);

    expect(sdk.options?.storage).toBe(window.localStorage);
  });

  it('caps how long a persisted session stays restorable at eight hours', () => {
    createCoreKitSession(ENV);

    expect(sdk.options?.sessionTime).toBe(28_800);
  });

  it('is cleared on logout, which the SDK leaves standing', async () => {
    const session = createCoreKitSession(ENV);
    window.localStorage.setItem(STORE_KEY, '{"sessionId":"a-session-id"}');

    await session.logout();

    expect(sdk.logoutCalls).toBe(1);
    expect(window.localStorage.getItem(STORE_KEY)).toBeNull();
  });

  it('is cleared when the SDK refuses to log out, and the refusal still surfaces', async () => {
    const session = createCoreKitSession(ENV);
    sdk.logoutError = REFUSED;
    window.localStorage.setItem(STORE_KEY, '{"sessionId":"a-session-id"}');

    await expect(session.logout()).rejects.toThrow(REFUSED);

    expect(window.localStorage.getItem(STORE_KEY)).toBeNull();
  });

  it('is cleared on a sign-out the SDK has no session to end', async () => {
    const session = createCoreKitSession(ENV);
    sdk.status = COREKIT_STATUS.NOT_INITIALIZED;
    window.localStorage.setItem(STORE_KEY, '{"sessionId":"a-session-id"}');

    await session.logout();

    expect(sdk.logoutCalls).toBe(0);
    expect(window.localStorage.getItem(STORE_KEY)).toBeNull();
  });

  it('is cleared when a login stops short of a session and the rollback is refused', async () => {
    const session = createCoreKitSession(ENV);
    sdk.statusAfterLogin = COREKIT_STATUS.REQUIRED_SHARE;
    sdk.logoutError = REFUSED;
    window.localStorage.setItem(STORE_KEY, '{"sessionId":"a-session-id"}');

    await expect(session.login('google')).rejects.toThrow(/needs approval or a recovery phrase/);

    expect(sdk.logoutCalls).toBe(1);
    expect(window.localStorage.getItem(STORE_KEY)).toBeNull();
  });
});
