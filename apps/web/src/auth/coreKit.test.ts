import {
  COREKIT_STATUS,
  FactorKeyTypeShareDescription,
  keyToMnemonic,
  TssShareType,
} from '@web3auth/mpc-core-kit';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryKeys, sealedTestStore } from '../test/storeFakes';
import type { SealedStore } from './sealedStore';
import { createCoreKitSession } from './coreKit';
import { RecoveryRequiredError, type IdentityCredential } from '@cipherbox/login';

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
  /** The factor this device has stored, if any; `undefined` is a fresh device. */
  deviceFactor: undefined as string | undefined,
  /** The one factor key that reconstructs; anything else is refused. */
  opensWith: undefined as string | undefined,
  inputs: [] as string[],
  created: [] as Record<string, unknown>[],
  setDeviceFactors: 0,
  commits: 0,
  totalFactors: 2,
  /** What `getKeyDetails` reports, so an enrollment can be seen to move it. */
  accountKey: 'aa',
  accountKeyAfterEnroll: undefined as string | undefined,
  enableMfaParams: undefined as Record<string, unknown> | undefined,
  enableMfaResult: 'ab'.repeat(32),
  enableMfaError: undefined as Error | undefined,
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
        sdk.commits += 1;
        return Promise.resolve();
      }
      logout(): Promise<void> {
        sdk.logoutCalls += 1;
        return sdk.logoutError ? Promise.reject(sdk.logoutError) : Promise.resolve();
      }
      getDeviceFactor(): Promise<string | undefined> {
        return Promise.resolve(sdk.deviceFactor);
      }
      inputFactorKey(factorKey: { toString(base: string): string }): Promise<void> {
        const hex = factorKey.toString('hex');
        sdk.inputs.push(hex);
        if (hex !== sdk.opensWith) return Promise.reject(new Error(`no share for ${hex}`));
        sdk.status = COREKIT_STATUS.LOGGED_IN;
        return Promise.resolve();
      }
      createFactor(params: Record<string, unknown>): Promise<string> {
        sdk.created.push(params);
        return Promise.resolve('factor');
      }
      setDeviceFactor(): Promise<void> {
        sdk.setDeviceFactors += 1;
        return Promise.resolve();
      }
      getKeyDetails(): Record<string, unknown> {
        const key = sdk.accountKey;
        return {
          totalFactors: sdk.totalFactors,
          tssPubKey: { x: { toString: () => key }, y: { toString: () => key } },
        };
      }
      enableMFA(params: Record<string, unknown>): Promise<string> {
        sdk.enableMfaParams = params;
        if (sdk.enableMfaError) return Promise.reject(sdk.enableMfaError);
        if (sdk.accountKeyAfterEnroll) sdk.accountKey = sdk.accountKeyAfterEnroll;
        return Promise.resolve(sdk.enableMfaResult);
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
  sdk.deviceFactor = undefined;
  sdk.opensWith = undefined;
  sdk.inputs = [];
  sdk.created = [];
  sdk.setDeviceFactors = 0;
  sdk.commits = 0;
  sdk.totalFactors = 2;
  sdk.accountKey = 'aa';
  sdk.accountKeyAfterEnroll = undefined;
  sdk.enableMfaParams = undefined;
  sdk.enableMfaError = undefined;
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

  it('is left standing by a login that stops at the factor policy', async () => {
    const created = session();
    sdk.statusAfterLogin = COREKIT_STATUS.REQUIRED_SHARE;
    await store.setItem(STORE_KEY, SESSION);

    await expect(created.login(credential())).rejects.toBeInstanceOf(RecoveryRequiredError);

    // Ending it here would make every factor-policy login a lockout: the phrase
    // is redeemed against exactly this half-open session.
    expect(sdk.logoutCalls).toBe(0);
    expect(window.localStorage.getItem(STORE_KEY)).not.toBeNull();
  });

  it('is cleared when a member abandons a login held at the factor policy', async () => {
    const created = session();
    sdk.statusAfterLogin = COREKIT_STATUS.REQUIRED_SHARE;
    await store.setItem(STORE_KEY, SESSION);
    await expect(created.login(credential())).rejects.toBeInstanceOf(RecoveryRequiredError);

    await created.logout();

    // A session short of reconstruction is still a live credential on the device.
    expect(sdk.logoutCalls).toBe(1);
    expect(window.localStorage.getItem(STORE_KEY)).toBeNull();
  });
});

describe('the recovery phrase as a login', () => {
  const FACTOR_HEX = 'ab'.repeat(32);
  const PHRASE = keyToMnemonic(FACTOR_HEX);

  /** A device that reached the factor policy holding no factor of its own. */
  async function heldAtPolicy(): Promise<ReturnType<typeof session>> {
    const created = session();
    sdk.statusAfterLogin = COREKIT_STATUS.REQUIRED_SHARE;
    await expect(created.login(credential())).rejects.toBeInstanceOf(RecoveryRequiredError);
    return created;
  }

  it('reads back the factor this device already holds, so a re-login is ordinary', async () => {
    const created = session();
    sdk.statusAfterLogin = COREKIT_STATUS.REQUIRED_SHARE;
    sdk.deviceFactor = FACTOR_HEX;
    sdk.opensWith = FACTOR_HEX;

    await created.login(credential());

    // The SDK's own reconstruct tries the deleted hashed share and stops; without
    // this read every re-login on an enrolled device would look like a lockout.
    expect(sdk.inputs).toEqual([FACTOR_HEX]);
    expect(created.isLoggedIn()).toBe(true);
  });

  it('opens the account from the phrase and mints this device a factor of its own', async () => {
    const created = await heldAtPolicy();
    sdk.opensWith = FACTOR_HEX;

    await created.recoverWithPhrase(` ${PHRASE.toUpperCase()}  `);

    expect(sdk.inputs).toEqual([FACTOR_HEX]);
    expect(created.isLoggedIn()).toBe(true);
    expect(sdk.created).toEqual([expect.objectContaining({ shareType: TssShareType.DEVICE })]);
    expect(sdk.setDeviceFactors).toBe(1);
    expect(sdk.commits).toBeGreaterThan(0);
  });

  it('refuses a wrong phrase without ending the session or clearing the store', async () => {
    const created = await heldAtPolicy();
    await store.setItem(STORE_KEY, SESSION);
    sdk.opensWith = 'cd'.repeat(32);

    await expect(created.recoverWithPhrase(PHRASE)).rejects.toThrow(/does not open this account/);

    expect(sdk.logoutCalls).toBe(0);
    expect(window.localStorage.getItem(STORE_KEY)).not.toBeNull();
    expect(sdk.created).toEqual([]);

    // Still held at the policy, so the member can type it again.
    sdk.opensWith = FACTOR_HEX;
    await expect(created.recoverWithPhrase(PHRASE)).resolves.toBeUndefined();
  });

  it('refuses a phrase that is not a phrase, quoting none of it back', async () => {
    const created = await heldAtPolicy();

    await expect(created.recoverWithPhrase('correct horse battery staple')).rejects.toThrow(
      /not a valid recovery phrase/
    );

    expect(sdk.inputs).toEqual([]);
  });
});

describe('recovery phrase enrollment', () => {
  const enrolled = async () => {
    const created = session();
    await created.login(credential());
    return created;
  };

  it('cuts the factor policy and returns the phrase, labelled so a later read can tell', async () => {
    const created = await enrolled();

    const phrase = await created.enrollRecoveryPhrase();

    expect(phrase.split(' ')).toHaveLength(24);
    // Web3Auth labels an unnamed factor "Other", which no later read can tell
    // apart from a device factor.
    expect(sdk.enableMfaParams).toEqual({
      shareDescription: FactorKeyTypeShareDescription.SeedPhrase,
    });
  });

  it('refuses to hand back a phrase for an account key that moved under it', async () => {
    const created = await enrolled();
    sdk.accountKeyAfterEnroll = 'bb';

    // The login secret is the vault's root seed: a moved key would make the
    // phrase open a vault holding none of the member's bytes.
    await expect(created.enrollRecoveryPhrase()).rejects.toThrow(/account key changed/);
  });

  it('reports a policy only past the two factors every fresh account carries', async () => {
    const created = await enrolled();
    expect(created.hasRecoveryPhrase()).toBe(false);

    sdk.totalFactors = 3;
    expect(created.hasRecoveryPhrase()).toBe(true);
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

  // The Google client ID configures the Google button alone; a build without one
  // must still seat an email or wallet login rather than refuse every session.
  it('is built by a bundle carrying no Google client ID', async () => {
    const withoutGoogle = createCoreKitSession({ ...ENV, VITE_GOOGLE_CLIENT_ID: undefined }, store);

    await withoutGoogle.login(credential({ method: 'email', verifierId: 'subject-42' }));
    expect(sdk.jwtLogin).toMatchObject({ verifier: 'verifier', verifierId: 'subject-42' });

    await withoutGoogle.login(credential({ method: 'wallet', verifierId: 'subject-42' }));
    expect(sdk.jwtLogin).toMatchObject({ verifier: 'verifier', verifierId: 'subject-42' });
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
