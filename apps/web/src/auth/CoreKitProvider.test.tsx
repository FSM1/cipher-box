import { act, renderHook, waitFor } from '@testing-library/react';
import { COREKIT_STATUS } from '@web3auth/mpc-core-kit';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createCoreKitSession } from './coreKit';
import { CoreKitProvider, useCoreKit } from './CoreKitProvider';

const STORE_KEY = 'corekit_store';
/** A truncated write, which is what an evicted or half-flushed store looks like. */
const CORRUPT_STORE = '{"sessionId":"a-sessio';
const SIGNED_OUT_STORE = '{"deviceFactor":"a-device-factor"}';
const LOGGED_IN_STORE = '{"sessionId":"a-fresh-session-id"}';
/** The SDK's own feature check is a bare `fetch`, so a restore fails offline. */
const OFFLINE = new Error('Failed to fetch');

// The SDK reads its store through a bare `JSON.parse` on both the restore and
// the login path, so one unreadable blob defeats every later login too. The
// fake reproduces that read, and the network leg that follows it in `init`.
const sdk = vi.hoisted(() => ({
  status: 'NOT_INITIALIZED',
  initFailure: undefined as Error | undefined,
}));
vi.mock('@web3auth/mpc-core-kit', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@web3auth/mpc-core-kit')>();
  const readStore = (): unknown => JSON.parse(window.localStorage.getItem(STORE_KEY) ?? '{}');
  return {
    ...actual,
    Web3AuthMPCCoreKit: class {
      readonly _storageKey = STORE_KEY;
      get status(): string {
        return sdk.status;
      }
      async init(): Promise<void> {
        readStore();
        if (sdk.initFailure) throw sdk.initFailure;
      }
      async loginWithOAuth(): Promise<void> {
        readStore();
        window.localStorage.setItem(STORE_KEY, LOGGED_IN_STORE);
        sdk.status = actual.COREKIT_STATUS.LOGGED_IN;
      }
      commitChanges(): Promise<void> {
        return Promise.resolve();
      }
    },
  };
});

const ENV = {
  VITE_WEB3AUTH_CLIENT_ID: 'client-id',
  VITE_WEB3AUTH_VERIFIER: 'verifier',
} satisfies Partial<ImportMetaEnv>;

/** The provider over a real Core Kit session, so the store it owns is the real one. */
function mount() {
  return renderHook(() => useCoreKit(), {
    wrapper: ({ children }: { children: ReactNode }) => (
      <CoreKitProvider createSession={() => createCoreKitSession(ENV)}>{children}</CoreKitProvider>
    ),
  });
}

describe('CoreKitProvider', () => {
  beforeEach(() => {
    sdk.status = COREKIT_STATUS.NOT_INITIALIZED;
    sdk.initFailure = undefined;
    window.localStorage.clear();
  });

  it('discards a store the restore could not read, and does not pass it off as a signed-out tab', async () => {
    window.localStorage.setItem(STORE_KEY, CORRUPT_STORE);
    const { result } = mount();

    await waitFor(() => expect(result.current.status).toBe('ready'));

    expect(result.current.error).toMatch(/could not be restored/);
    expect(result.current.session?.isLoggedIn()).toBe(false);
    expect(window.localStorage.getItem(STORE_KEY)).toBeNull();
  });

  it('leaves a login after a failed restore able to establish a session', async () => {
    window.localStorage.setItem(STORE_KEY, CORRUPT_STORE);
    const { result } = mount();
    await waitFor(() => expect(result.current.status).toBe('ready'));

    await act(async () => {
      await result.current.session?.login('google');
    });

    expect(result.current.session?.isLoggedIn()).toBe(true);
    expect(window.localStorage.getItem(STORE_KEY)).toBe(LOGGED_IN_STORE);
  });

  it('keeps a readable store when the restore failed for some other reason', async () => {
    window.localStorage.setItem(STORE_KEY, SIGNED_OUT_STORE);
    sdk.initFailure = OFFLINE;
    const { result } = mount();

    await waitFor(() => expect(result.current.status).toBe('ready'));

    expect(result.current.error).toMatch(/could not be restored/);
    expect(window.localStorage.getItem(STORE_KEY)).toBe(SIGNED_OUT_STORE);
  });

  it('keeps a store the restore read cleanly, session in it or not', async () => {
    window.localStorage.setItem(STORE_KEY, SIGNED_OUT_STORE);
    const { result } = mount();

    await waitFor(() => expect(result.current.status).toBe('ready'));

    expect(result.current.error).toBeNull();
    expect(result.current.session?.isLoggedIn()).toBe(false);
    expect(window.localStorage.getItem(STORE_KEY)).toBe(SIGNED_OUT_STORE);
  });
});
