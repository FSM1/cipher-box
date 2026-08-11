import { act, renderHook, waitFor } from '@testing-library/react';
import { COREKIT_STATUS } from '@web3auth/mpc-core-kit';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { sealedTestStore } from '../test/storeFakes';
import { createCoreKitSession } from './coreKit';
import type { SealedStore } from './sealedStore';
import { CoreKitProvider, useCoreKit } from './CoreKitProvider';

const STORE_KEY = 'corekit_store';
/** Every store shape the SDK's read throws on, since it parses and then indexes. */
const UNREADABLE_STORES: [string, string][] = [
  // What an evicted or half-flushed write looks like: the parse itself throws.
  ['a truncated write', '{"sessionId":"a-sessio'],
  // Parses cleanly, then the index step throws because `null` has no keys.
  ['a null literal', 'null'],
];
const SIGNED_OUT_STORE = '{"deviceFactor":"a-device-factor"}';
const LOGGED_IN_STORE = '{"sessionId":"a-fresh-session-id"}';
/** The SDK's own feature check is a bare `fetch`, so a restore fails offline. */
const OFFLINE = new Error('Failed to fetch');

/** The `IAsyncStorage` surface the SDK drives, which is what the seal implements. */
interface AsyncStore {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
}

// The SDK reads its store as `JSON.parse(raw || '{}')[key]` (`AsyncStorage.get`,
// which `init` calls for `sessionId`) on both the restore and the login path, so
// one unreadable blob defeats every later login too. The fake reproduces that
// read — parse *and* index — and the network leg that follows it in `init`.
const sdk = vi.hoisted(() => ({
  status: 'NOT_INITIALIZED',
  initFailure: undefined as Error | undefined,
}));
vi.mock('@web3auth/mpc-core-kit', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@web3auth/mpc-core-kit')>();
  return {
    ...actual,
    Web3AuthMPCCoreKit: class {
      readonly _storageKey = STORE_KEY;
      private readonly storage: AsyncStore;
      constructor(options: { storage: AsyncStore }) {
        this.storage = options.storage;
      }
      get status(): string {
        return sdk.status;
      }
      private async readStore(): Promise<void> {
        const raw = (await this.storage.getItem(STORE_KEY)) || '{}';
        void (JSON.parse(raw) as Record<string, unknown>).sessionId;
      }
      async init(): Promise<void> {
        await this.readStore();
        if (sdk.initFailure) throw sdk.initFailure;
      }
      async loginWithOAuth(): Promise<void> {
        await this.readStore();
        await this.storage.setItem(STORE_KEY, LOGGED_IN_STORE);
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
  VITE_GOOGLE_CLIENT_ID: 'google-client-id',
} satisfies Partial<ImportMetaEnv>;

describe('CoreKitProvider', () => {
  let store: SealedStore;

  /** The provider over a real Core Kit session, so the store it owns is the real one. */
  function mount() {
    return renderHook(() => useCoreKit(), {
      wrapper: ({ children }: { children: ReactNode }) => (
        <CoreKitProvider createSession={() => createCoreKitSession(ENV, store)}>
          {children}
        </CoreKitProvider>
      ),
    });
  }

  beforeEach(() => {
    sdk.status = COREKIT_STATUS.NOT_INITIALIZED;
    sdk.initFailure = undefined;
    window.localStorage.clear();
    store = sealedTestStore();
  });

  it.each(UNREADABLE_STORES)(
    'discards %s the restore could not read, and does not pass it off as a signed-out tab',
    async (_shape, seeded) => {
      await store.setItem(STORE_KEY, seeded);
      const { result } = mount();

      await waitFor(() => expect(result.current.status).toBe('ready'));

      expect(result.current.error).toMatch(/could not be restored/);
      expect(result.current.session?.isLoggedIn()).toBe(false);
      expect(window.localStorage.getItem(STORE_KEY)).toBeNull();
    }
  );

  it.each(UNREADABLE_STORES)(
    'leaves a login after a restore that failed on %s able to establish a session',
    async (_shape, seeded) => {
      await store.setItem(STORE_KEY, seeded);
      const { result } = mount();
      await waitFor(() => expect(result.current.status).toBe('ready'));

      await act(async () => {
        await result.current.session?.login('google');
      });

      expect(result.current.session?.isLoggedIn()).toBe(true);
      await expect(store.getItem(STORE_KEY)).resolves.toBe(LOGGED_IN_STORE);
    }
  );

  it('keeps a readable store when the restore failed for some other reason', async () => {
    await store.setItem(STORE_KEY, SIGNED_OUT_STORE);
    sdk.initFailure = OFFLINE;
    const { result } = mount();

    await waitFor(() => expect(result.current.status).toBe('ready'));

    expect(result.current.error).toMatch(/could not be restored/);
    await expect(store.getItem(STORE_KEY)).resolves.toBe(SIGNED_OUT_STORE);
  });

  it('keeps a store the restore read cleanly, session in it or not', async () => {
    await store.setItem(STORE_KEY, SIGNED_OUT_STORE);
    const { result } = mount();

    await waitFor(() => expect(result.current.status).toBe('ready'));

    expect(result.current.error).toBeNull();
    expect(result.current.session?.isLoggedIn()).toBe(false);
    await expect(store.getItem(STORE_KEY)).resolves.toBe(SIGNED_OUT_STORE);
  });
});
