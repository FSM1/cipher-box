import {
  COREKIT_STATUS,
  FactorKeyTypeShareDescription,
  keyToMnemonic,
  TssShareType,
} from '@web3auth/mpc-core-kit';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { deviceIdentitiesTestInstance, MemoryKeys, sealedTestStore } from '../test/storeFakes';
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
  /** The `replaceExisting` flag each `setDeviceFactor` carried. */
  setDeviceFactors: [] as unknown[],
  /** The factor scalars `deleteFactor` was asked to drop, hex. */
  deleted: [] as string[],
  deleteFactorError: undefined as Error | undefined,
  commits: 0,
  /** Which `commitChanges` call rejects, 1-based; `0` for none. */
  commitFailsAfter: 0,
  shareDescriptions: {} as Record<string, string[]>,
  /** Set to make the SDK's own factor read throw, as an unreachable one does. */
  keyDetailsError: undefined as Error | undefined,
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
        return sdk.commits === sdk.commitFailsAfter
          ? Promise.reject(new Error('metadata sync failed'))
          : Promise.resolve();
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
      setDeviceFactor(_factorKey: unknown, replaceExisting?: unknown): Promise<void> {
        sdk.setDeviceFactors.push(replaceExisting);
        return Promise.resolve();
      }
      deleteFactor(
        _factorPub: unknown,
        factorKey: { toString(base: string): string }
      ): Promise<void> {
        if (sdk.deleteFactorError) return Promise.reject(sdk.deleteFactorError);
        sdk.deleted.push(factorKey.toString('hex'));
        return Promise.resolve();
      }
      getKeyDetails(): Record<string, unknown> {
        if (sdk.keyDetailsError) throw sdk.keyDetailsError;
        const key = sdk.accountKey;
        return {
          shareDescriptions: sdk.shareDescriptions,
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

/** The identity subject every credential below signs in as. */
const SUBJECT = 'subject-42';

let keys: MemoryKeys;
let store: SealedStore;
let deviceIdentities: ReturnType<typeof deviceIdentitiesTestInstance>;

/** A session over a store this test can seed and read back. */
const session = () => createCoreKitSession(ENV, store, deviceIdentities);

/** What the identity exchange hands back, as the Core Kit seam takes it. */
const credential = (overrides: Partial<IdentityCredential> = {}): IdentityCredential => ({
  method: 'google',
  token: 'header.payload.signature',
  verifierId: SUBJECT,
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
  sdk.setDeviceFactors = [];
  sdk.deleted = [];
  sdk.deleteFactorError = undefined;
  sdk.commits = 0;
  sdk.commitFailsAfter = 0;
  sdk.shareDescriptions = {};
  sdk.keyDetailsError = undefined;
  sdk.accountKey = 'aa';
  sdk.accountKeyAfterEnroll = undefined;
  sdk.enableMfaParams = undefined;
  sdk.enableMfaError = undefined;
  window.localStorage.clear();
  keys = new MemoryKeys();
  store = sealedTestStore(keys);
  deviceIdentities = deviceIdentitiesTestInstance();
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

describe('forgetting this device with the account', () => {
  const DEVICE_FACTOR = 'cd'.repeat(32);

  // The identity key is selected by subject, so a session that never logged in
  // itself reads the signed-in member off the SDK, as a restored tab does.
  beforeEach(() => {
    sdk.userInfo = { verifierId: SUBJECT };
  });

  /** An account carrying a recovery phrase, so a dropped factor is not the last. */
  const enrolled = (): void => {
    sdk.shareDescriptions = {
      pub: [JSON.stringify({ module: FactorKeyTypeShareDescription.SeedPhrase })],
    };
  };

  it('drops the factor this device holds, and syncs the removal', async () => {
    enrolled();
    sdk.deviceFactor = DEVICE_FACTOR;

    await session().forgetDevice();

    expect(sdk.deleted).toEqual([DEVICE_FACTOR]);
    // Manual sync: an unsynced removal leaves the factor live on the account.
    expect(sdk.commits).toBe(1);
  });

  /**
   * The local erase destroys the only copy of this factor, so dropping it from
   * an account with no phrase behind it is a permanent lockout, not a cleanup.
   */
  it("leaves the factor standing when it is the account's last way in", async () => {
    sdk.shareDescriptions = {};
    sdk.deviceFactor = DEVICE_FACTOR;

    await session().forgetDevice();

    expect(sdk.deleted).toEqual([]);
  });

  it('asks the account for nothing when this device holds no factor', async () => {
    enrolled();
    sdk.deviceFactor = undefined;

    await session().forgetDevice();

    expect(sdk.deleted).toEqual([]);
    expect(sdk.commits).toBe(0);
  });

  /**
   * The erase beside this one has to land offline, so a refused drop is a
   * degraded outcome, never a failed forget.
   */
  it('does not fail the forget when the account cannot be reached', async () => {
    enrolled();
    sdk.deviceFactor = DEVICE_FACTOR;
    sdk.deleteFactorError = REFUSED;

    await expect(session().forgetDevice()).resolves.toBeUndefined();
  });

  /**
   * Unconditional, unlike the factor drop: an identity key left behind keeps
   * signing as a device the member erased.
   */
  it("erases this device's identity key even when the factor has to stand", async () => {
    sdk.shareDescriptions = {};
    sdk.deviceFactor = DEVICE_FACTOR;
    // Seeded through an identity of its own, so a key is really there to erase.
    await deviceIdentities.forSubject(SUBJECT).publicKeyHex();

    await session().forgetDevice();

    expect(sdk.deleted).toEqual([]);
    expect(deviceIdentities.keysFor(SUBJECT).held).toBeNull();
  });

  it('reports an identity erase the key store refused', async () => {
    enrolled();
    deviceIdentities.keysFor(SUBJECT).refusal = REFUSED;

    await expect(session().forgetDevice()).rejects.toThrow(REFUSED);
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
    // Replacing: a stored factor whose commit failed would otherwise refuse
    // every later mint and leave this device unable to finish a recovery.
    expect(sdk.setDeviceFactors).toEqual([true]);
    expect(sdk.commits).toBeGreaterThan(0);
  });

  it('opens the account even when the factor it mints for this device cannot be synced', async () => {
    const created = await heldAtPolicy();
    sdk.opensWith = FACTOR_HEX;
    // A login held at the policy commits nothing, so the sync after the mint is
    // the first commit this session makes.
    sdk.commitFailsAfter = 1;

    await expect(created.recoverWithPhrase(PHRASE)).resolves.toBeUndefined();

    // The account is open from here: raising would leave a live session this
    // device's own guard refuses to retry.
    expect(created.isLoggedIn()).toBe(true);
    expect(sdk.created).toHaveLength(1);
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

    const { phrase, warning } = await created.enrollRecoveryPhrase();

    expect(phrase.split(' ')).toHaveLength(24);
    expect(warning).toBeNull();
    expect(sdk.enableMfaParams).toEqual({
      shareDescription: FactorKeyTypeShareDescription.SeedPhrase,
    });
  });

  it('hands the phrase back even when the sync that follows the cut fails', async () => {
    const created = await enrolled();
    // The sync after the cut: the login's commit is 1, the pre-cut commit 2.
    sdk.commitFailsAfter = 3;

    const { phrase, warning } = await created.enrollRecoveryPhrase();

    // The cut deleted the hashed cloud share, so these words are the account's
    // only spare key: discarding them over a failed sync is a lockout.
    expect(phrase.split(' ')).toHaveLength(24);
    expect(warning).toMatch(/could not be synced/);
  });

  it('warns rather than withholds when the account key moved under the cut', async () => {
    const created = await enrolled();
    sdk.accountKeyAfterEnroll = 'bb';

    const { phrase, warning } = await created.enrollRecoveryPhrase();

    expect(phrase.split(' ')).toHaveLength(24);
    expect(warning).toMatch(/account key changed/);
  });

  it('reads the phrase off its factor label, not off a factor count', async () => {
    const created = await enrolled();
    // A device-approval factor would take the count past the two a fresh
    // account carries without a phrase ever having been shown.
    sdk.shareDescriptions = { ab: [JSON.stringify({ module: 'deviceShare' })] };
    expect(created.hasRecoveryPhrase()).toBe(false);

    sdk.shareDescriptions = {
      ab: [JSON.stringify({ module: 'deviceShare' })],
      cd: [JSON.stringify({ module: 'seedPhrase' })],
    };
    expect(created.hasRecoveryPhrase()).toBe(true);
  });

  it('reads the phrase off the share index too, which the SDK stamps on every factor', async () => {
    const created = await enrolled();
    // The label the SDK falls back to when a factor is created without one; the
    // index is what still tells a recovery factor from a device factor.
    sdk.shareDescriptions = {
      ab: [JSON.stringify({ module: 'Other', tssShareIndex: TssShareType.DEVICE })],
    };
    expect(created.hasRecoveryPhrase()).toBe(false);

    sdk.shareDescriptions = {
      ab: [JSON.stringify({ module: 'Other', tssShareIndex: TssShareType.DEVICE })],
      cd: [JSON.stringify({ module: 'Other', tssShareIndex: TssShareType.RECOVERY })],
    };
    expect(created.hasRecoveryPhrase()).toBe(true);
  });

  it('reports no phrase for a description entry it cannot parse', () => {
    const created = session();
    sdk.shareDescriptions = { ab: ['not json'] };
    expect(created.hasRecoveryPhrase()).toBe(false);
  });

  it('reports no phrase when the SDK will not hand over the factor list at all', () => {
    const created = session();
    sdk.keyDetailsError = new Error('the key details are unreadable');
    expect(created.hasRecoveryPhrase()).toBe(false);
  });

  /**
   * The account-wide reading the approver poll runs on: a device-approval
   * factor is a policy even though it is not a phrase.
   */
  it('reads the policy off the factor count, which any factor kind moves', () => {
    const created = session();
    sdk.shareDescriptions = {
      ab: [JSON.stringify({ module: 'deviceShare' })],
      cd: [JSON.stringify({ module: 'deviceShare' })],
    };
    expect(created.hasFactorPolicy()).toBe(false);

    sdk.shareDescriptions = {
      ab: [JSON.stringify({ module: 'deviceShare' })],
      cd: [JSON.stringify({ module: 'deviceShare' })],
      ef: [JSON.stringify({ module: 'deviceShare' })],
    };
    expect(created.hasFactorPolicy()).toBe(true);
    expect(created.hasRecoveryPhrase()).toBe(false);
  });

  it('reports no policy when the SDK will not hand over the factor list at all', () => {
    const created = session();
    sdk.keyDetailsError = new Error('the key details are unreadable');
    expect(created.hasFactorPolicy()).toBe(false);
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
    const withoutGoogle = createCoreKitSession(
      { ...ENV, VITE_GOOGLE_CLIENT_ID: undefined },
      store,
      deviceIdentities
    );

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

  it('raises the recovery prompt for a factor policy and for nothing else', async () => {
    const created = session();
    sdk.statusAfterLogin = COREKIT_STATUS.INITIALIZED;

    const failure = await created.login(credential()).catch((error: unknown) => error);

    // A phrase cannot answer this, so offering the panel would strand the
    // member at a prompt its own guard refuses.
    expect(failure).toBeInstanceOf(Error);
    expect(failure).not.toBeInstanceOf(RecoveryRequiredError);
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
