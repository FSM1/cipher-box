import { COREKIT_STATUS } from '@web3auth/mpc-core-kit';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryKeys, sealedTestStore } from '../test/storeFakes';
import type { SealedStore } from './sealedStore';
import { createCoreKitSession } from './coreKit';
import type { IdentityCredential } from './identityExchange';

const STORE_KEY = 'corekit_store';

/** What the SDK writes under its one key; nothing here is real key material. */
const SESSION = '{"sessionId":"not-a-real-session-id"}';

// The SDK reaches for the Web3Auth network on construction; the seam is what
// lets the persistence options it is handed be read back, and what drives the
// login and logout outcomes a device can actually land in.
const sdk = vi.hoisted(() => ({
  options: undefined as Record<string, unknown> | undefined,
  jwtLogin: undefined as Record<string, unknown> | undefined,
  userInfo: undefined as Record<string, unknown> | undefined,
  status: 'LOGGED_IN',
  statusAfterLogin: 'LOGGED_IN',
  logoutError: undefined as Error | undefined,
  logoutCalls: 0,
  initFailure: undefined as Error | undefined,
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
      init(): Promise<void> {
        return sdk.initFailure ? Promise.reject(sdk.initFailure) : Promise.resolve();
      }
      async loginWithJWT(params: Record<string, unknown>): Promise<void> {
        sdk.jwtLogin = params;
        sdk.status = sdk.statusAfterLogin;
      }
      getUserInfo(): Record<string, unknown> {
        if (!sdk.userInfo) throw new Error('no user info');
        return sdk.userInfo;
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
  VITE_WEB3AUTH_CLIENT_ID: 'web3auth-client-id',
  VITE_WEB3AUTH_VERIFIER: 'verifier',
  VITE_GOOGLE_CLIENT_ID: 'google-client-id',
} satisfies Partial<ImportMetaEnv>;

const REFUSED = new Error('the session server is unreachable');

let keys: MemoryKeys;
let store: SealedStore;

/** A session over a store this test can seed and read back. */
const session = () => createCoreKitSession(ENV, store);

/** What the identity exchange hands back, as the Core Kit seam takes it. */
const credential = (overrides: Partial<IdentityCredential> = {}): IdentityCredential => ({
  method: 'google',
  token: 'header.payload.signature',
  verifierId: 'subject-42',
  email: null,
  ...overrides,
});

beforeEach(() => {
  sdk.options = undefined;
  sdk.jwtLogin = undefined;
  sdk.userInfo = undefined;
  sdk.status = COREKIT_STATUS.LOGGED_IN;
  sdk.statusAfterLogin = COREKIT_STATUS.LOGGED_IN;
  sdk.logoutError = undefined;
  sdk.logoutCalls = 0;
  sdk.initFailure = undefined;
  window.localStorage.clear();
  keys = new MemoryKeys();
  store = sealedTestStore(keys);
});

describe('the Core Kit store', () => {
  it('hands the SDK the sealed store, so nothing it writes lands in the clear', async () => {
    session();
    await store.setItem(STORE_KEY, SESSION);

    expect(sdk.options?.storage).toBe(store);
    expect(window.localStorage.getItem(STORE_KEY)).not.toContain('sessionId');
  });

  it('is left standing when a restore failed only because the key store was unreachable', async () => {
    // Seeded through a store of its own, so the session's has no key in hand
    // and has to reach the one that is about to refuse.
    await sealedTestStore(keys).setItem(STORE_KEY, SESSION);
    const stored = window.localStorage.getItem(STORE_KEY);
    keys.refusal = new Error('the wrapping-key database is shut');
    sdk.initFailure = REFUSED;

    await expect(session().restore()).rejects.toThrow(REFUSED);

    expect(window.localStorage.getItem(STORE_KEY)).toBe(stored);
    expect(keys.held).not.toBeNull();
  });

  it('is cleared when a restore found something the SDK could not parse', async () => {
    const created = session();
    await store.setItem(STORE_KEY, '{"sessionId":"a-truncated-writ');
    sdk.initFailure = REFUSED;

    await expect(created.restore()).rejects.toThrow(REFUSED);

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

    await expect(created.login(credential())).rejects.toThrow(
      /needs approval or a recovery phrase/
    );

    expect(sdk.logoutCalls).toBe(1);
    expect(window.localStorage.getItem(STORE_KEY)).toBeNull();
  });
});

describe('a Core Kit login', () => {
  it('names the Web3Auth project to the SDK itself', () => {
    session();

    expect(sdk.options?.web3AuthClientId).toBe('web3auth-client-id');
  });

  // The CipherBox verifier, not a Torus-hosted sub-verifier: the token is
  // CipherBox's and the Core Kit checks it against CipherBox's own JWKS.
  it('redeems the CipherBox identity token against the CipherBox verifier', async () => {
    await session().login(credential({ method: 'wallet', verifierId: 'subject-42' }));

    expect(sdk.jwtLogin).toMatchObject({
      verifier: 'verifier',
      verifierId: 'subject-42',
      idToken: 'header.payload.signature',
    });
  });

  it('reaches one identity from every method, given one subject', async () => {
    await session().login(credential({ method: 'google', verifierId: 'shared-subject' }));
    const viaGoogle = sdk.jwtLogin;
    await session().login(credential({ method: 'wallet', verifierId: 'shared-subject' }));

    expect(sdk.jwtLogin?.verifierId).toBe(viaGoogle?.verifierId);
    expect(sdk.jwtLogin?.verifier).toBe(viaGoogle?.verifier);
  });

  it('reports the method off the token claim the SDK parsed, so a restore keeps it', () => {
    sdk.userInfo = { verifierId: 'subject-42', method: 'wallet' };

    expect(session().method()).toBe('wallet');
  });

  it('names no method when the session carries nothing it recognizes', () => {
    sdk.userInfo = { verifierId: 'subject-42', method: 'carrier-pigeon' };
    expect(session().method()).toBeNull();

    sdk.userInfo = undefined;
    expect(session().method()).toBeNull();
  });

  it('reports the address the exchange gave it, and drops it on logout', async () => {
    const created = session();
    expect(created.email()).toBeNull();

    await created.login(credential({ method: 'email', email: 'member@example.test' }));
    expect(created.email()).toBe('member@example.test');

    await created.logout();
    expect(created.email()).toBeNull();
  });
});
