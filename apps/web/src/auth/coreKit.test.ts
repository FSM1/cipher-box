import { describe, expect, it, vi } from 'vitest';
import { createCoreKitSession } from './coreKit';

const STORE_KEY = 'corekit_store';

// The SDK reaches for the Web3Auth network on construction; the seam is what
// lets the persistence options it is handed be read back.
const built = vi.hoisted(() => ({ options: undefined as Record<string, unknown> | undefined }));
vi.mock('@web3auth/mpc-core-kit', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@web3auth/mpc-core-kit')>();
  return {
    ...actual,
    Web3AuthMPCCoreKit: class {
      readonly _storageKey = STORE_KEY;
      readonly status = actual.COREKIT_STATUS.LOGGED_IN;
      constructor(options: Record<string, unknown>) {
        built.options = options;
      }
      logout(): Promise<void> {
        return Promise.resolve();
      }
    },
  };
});

const ENV = {
  VITE_WEB3AUTH_CLIENT_ID: 'client-id',
  VITE_WEB3AUTH_VERIFIER: 'verifier',
} satisfies Partial<ImportMetaEnv>;

describe('the Core Kit store', () => {
  it('persists origin-wide, so a tab that did not log in can still be promoted to leader', () => {
    createCoreKitSession(ENV);

    expect(built.options?.storage).toBe(window.localStorage);
  });

  it('caps how long a persisted session stays restorable, below the SDK default', () => {
    createCoreKitSession(ENV);

    // The SDK restores its own 86400s default on a falsy value, so an upper
    // bound alone would pass on `0`.
    expect(built.options?.sessionTime).toBeGreaterThan(0);
    expect(built.options?.sessionTime).toBeLessThan(86_400);
  });

  it('is cleared on logout, which the SDK leaves standing', async () => {
    const session = createCoreKitSession(ENV);
    window.localStorage.setItem(STORE_KEY, '{"sessionId":"a-session-id"}');

    await session.logout();

    expect(window.localStorage.getItem(STORE_KEY)).toBeNull();
  });
});
