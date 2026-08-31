import { beforeEach, describe, expect, it, vi } from 'vitest';
import { RecoveryRequiredError, type IdentityCredential } from '@cipherbox/login';
import { invoke } from '@tauri-apps/api/core';
import type { DesktopConfig } from '../config';
import { createCoreKitSession } from './coreKit';

/** What the SDK is handed as its store, and what the shell put behind it. */
interface CoreKitStorage {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  purge(): Promise<void>;
}

/** A 24-word phrase's shape; the SDK's own decoder is faked below. */
const PHRASE = Array.from({ length: 24 }, (_, word) => `word${String(word)}`).join(' ');
const PHRASE_KEY = '0f'.repeat(32);

const sdk = vi.hoisted(() => ({
  status: 'logged-in',
  storage: null as CoreKitStorage | null,
  logout: vi.fn((): Promise<void> => Promise.resolve()),
  loginWithJWT: vi.fn((): Promise<void> => Promise.resolve()),
  commitChanges: vi.fn((): Promise<void> => Promise.resolve()),
  getDeviceFactor: vi.fn((): Promise<string | undefined> => Promise.resolve(undefined)),
  inputFactorKey: vi.fn((): Promise<void> => Promise.resolve()),
  createFactor: vi.fn((): Promise<string> => Promise.resolve('a-new-factor')),
  setDeviceFactor: vi.fn((): Promise<void> => Promise.resolve()),
  mnemonicToKey: vi.fn((_phrase: string): string => '00'),
}));

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@toruslabs/tss-dkls-lib', () => ({ tssLib: {} }));
vi.mock('@cipherbox/login', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@cipherbox/login')>()),
  accountIdFromTssPoint: () => 'an-account-id',
  isIdentityMethod: (method: unknown) => method === 'google',
}));
vi.mock('@web3auth/mpc-core-kit', () => ({
  COREKIT_STATUS: { LOGGED_IN: 'logged-in', REQUIRED_SHARE: 'needs-a-share' },
  WEB3AUTH_NETWORK: { MAINNET: 'mainnet', DEVNET: 'devnet' },
  FactorKeyTypeShareDescription: { DeviceShare: 'device-share' },
  TssShareType: { DEVICE: 2 },
  generateFactorKey: () => ({ private: 'a-scalar', pub: 'a-point' }),
  mnemonicToKey: sdk.mnemonicToKey,
  Web3AuthMPCCoreKit: class {
    constructor(options: { storage: CoreKitStorage }) {
      sdk.storage = options.storage;
    }
    get status(): string {
      return sdk.status;
    }
    init = (): Promise<void> => Promise.resolve();
    loginWithJWT = sdk.loginWithJWT;
    commitChanges = sdk.commitChanges;
    logout = sdk.logout;
    getDeviceFactor = sdk.getDeviceFactor;
    inputFactorKey = sdk.inputFactorKey;
    createFactor = sdk.createFactor;
    setDeviceFactor = sdk.setDeviceFactor;
  },
}));

const ipc = vi.mocked(invoke);

const config = {
  web3AuthClientId: 'a-client',
  environment: 'ci',
  verifier: 'a-verifier',
} as DesktopConfig;

const credential: IdentityCredential = {
  method: 'google',
  token: 'an-identity-token',
  verifierId: 'a-verifier-id',
  email: 'member@example.com',
};

/** The store the SDK was handed by the session under test. */
function storage(): CoreKitStorage {
  const held = sdk.storage;
  if (held === null) throw new Error('the SDK was handed no store');
  return held;
}

/** Reaches the phrase prompt, which every recovery test starts from. */
async function heldAtTheFactorPolicy() {
  sdk.status = 'needs-a-share';
  const session = createCoreKitSession(config);
  await expect(session.login(credential)).rejects.toBeInstanceOf(RecoveryRequiredError);
  return session;
}

beforeEach(() => {
  vi.resetAllMocks();
  ipc.mockResolvedValue(null);
  sdk.getDeviceFactor.mockResolvedValue(undefined);
  sdk.mnemonicToKey.mockReturnValue(PHRASE_KEY);
  sdk.createFactor.mockResolvedValue('a-new-factor');
  sdk.status = 'logged-in';
  sdk.storage = null;
});

describe("the shell's Core Kit store", () => {
  it('reads and writes through the shell rather than this process', async () => {
    createCoreKitSession(config);

    await storage().setItem('corekit_store', 'a device factor');
    expect(ipc).toHaveBeenCalledWith('core_kit_set_item', {
      key: 'corekit_store',
      value: 'a device factor',
    });

    ipc.mockResolvedValueOnce('a device factor');
    await expect(storage().getItem('corekit_store')).resolves.toBe('a device factor');
    expect(ipc).toHaveBeenCalledWith('core_kit_get_item', { key: 'corekit_store' });
  });

  // The SDK's own logout blanks its session id and leaves the rest of its store
  // standing, a device factor share among it.
  it('drops the whole store on a sign-out, not just the SDK session id', async () => {
    const session = createCoreKitSession(config);

    await session.logout();

    expect(sdk.logout).toHaveBeenCalled();
    expect(ipc).toHaveBeenCalledWith('core_kit_purge');
  });

  it('reports a store that refused the drop rather than signing out in silence', async () => {
    const session = createCoreKitSession(config);
    ipc.mockRejectedValue(new Error('the keyring is locked'));

    await expect(session.logout()).rejects.toThrow('the keyring is locked');
    expect(sdk.logout).toHaveBeenCalled();
  });
});

describe('a sign-in that meets a factor policy', () => {
  // The phrase is redeemed against this very login, so ending it here would
  // make every such sign-in a lockout (ADR 0009 D2).
  it('holds the login open and asks for the recovery phrase', async () => {
    await heldAtTheFactorPolicy();

    expect(ipc).not.toHaveBeenCalledWith('core_kit_purge');
    expect(sdk.logout).not.toHaveBeenCalled();
  });

  // The SDK's own reconstruct tries the hashed share the policy deleted, so a
  // device that does hold a factor stops short unless the factor is read back.
  it('reads this device stored factor before it calls the login a lockout', async () => {
    sdk.status = 'needs-a-share';
    sdk.getDeviceFactor.mockResolvedValue('0a'.repeat(32));
    sdk.inputFactorKey.mockImplementation(() => {
      sdk.status = 'logged-in';
      return Promise.resolve();
    });
    const session = createCoreKitSession(config);

    await expect(session.login(credential)).resolves.toBeUndefined();
    expect(sdk.commitChanges).toHaveBeenCalled();
  });

  it('refuses any other stalled status rather than offering a phrase for it', async () => {
    sdk.status = 'not-initialized';
    const session = createCoreKitSession(config);

    const failure = await session.login(credential).catch((error: unknown) => error);
    expect(failure).not.toBeInstanceOf(RecoveryRequiredError);
    expect(failure).toBeInstanceOf(Error);
  });

  // A session held short of reconstruction is still a live credential.
  it('ends the held login when the member abandons the prompt', async () => {
    const session = await heldAtTheFactorPolicy();

    await session.logout();

    expect(sdk.logout).toHaveBeenCalled();
    expect(ipc).toHaveBeenCalledWith('core_kit_purge');
  });
});

describe('the recovery phrase as a login', () => {
  it('reads a typed phrase the one way, whatever the case and spacing', async () => {
    const session = await heldAtTheFactorPolicy();
    sdk.inputFactorKey.mockImplementation(() => {
      sdk.status = 'logged-in';
      return Promise.resolve();
    });

    await session.recoverWithPhrase(`  ${PHRASE.toUpperCase()}  `);

    expect(sdk.mnemonicToKey).toHaveBeenCalledWith(PHRASE);
  });

  // Without a factor of its own this device asks for the phrase at every
  // launch, which is the per-launch ritual the keyring store exists to end.
  it('mints this device a factor once the phrase opens the account', async () => {
    const session = await heldAtTheFactorPolicy();
    sdk.inputFactorKey.mockImplementation(() => {
      sdk.status = 'logged-in';
      return Promise.resolve();
    });

    await session.recoverWithPhrase(PHRASE);

    expect(sdk.createFactor).toHaveBeenCalled();
    expect(sdk.setDeviceFactor).toHaveBeenCalledWith('a-scalar', true);
    expect(sdk.commitChanges).toHaveBeenCalled();
  });

  // The account is open by then, so raising would leave a live session this
  // device's own guard refuses to retry.
  it('signs the member in even when the device factor could not be minted', async () => {
    const session = await heldAtTheFactorPolicy();
    sdk.inputFactorKey.mockImplementation(() => {
      sdk.status = 'logged-in';
      return Promise.resolve();
    });
    sdk.createFactor.mockRejectedValue(new Error('the account could not be re-synced'));

    await expect(session.recoverWithPhrase(PHRASE)).resolves.toBeUndefined();
    expect(session.isLoggedIn()).toBe(true);
  });

  it('leaves the login held when the phrase does not open the account', async () => {
    const session = await heldAtTheFactorPolicy();
    sdk.inputFactorKey.mockRejectedValue(new Error('reconstruction failed'));

    await expect(session.recoverWithPhrase(PHRASE)).rejects.toThrow(/did not open this account/);
    expect(session.isLoggedIn()).toBe(false);
    expect(ipc).not.toHaveBeenCalledWith('core_kit_purge');
  });

  it('leaves the login held when the SDK stops short of a session', async () => {
    const session = await heldAtTheFactorPolicy();

    await expect(session.recoverWithPhrase(PHRASE)).rejects.toThrow(/did not open this account/);
    expect(session.isLoggedIn()).toBe(false);
  });

  // Both the decoder's message and the SDK's quote what they were handed, and
  // what they were handed is the member's phrase.
  it('never repeats the typed phrase in what it reports', async () => {
    const session = await heldAtTheFactorPolicy();
    sdk.mnemonicToKey.mockImplementation((typed: string) => {
      throw new Error(`bad mnemonic: ${typed}`);
    });

    const failure = await session.recoverWithPhrase(PHRASE).catch((error: unknown) => error);
    expect(String(failure)).not.toContain('word0');
    expect(String(failure)).toContain('not a valid recovery phrase');
  });

  // The phrase never leaves this window: the SDK reads it, and what crosses the
  // IPC seam is the sealed store slot and a freshly minted factor.
  it('never hands the typed phrase to the shell process', async () => {
    const session = await heldAtTheFactorPolicy();
    sdk.inputFactorKey.mockImplementation(() => {
      sdk.status = 'logged-in';
      return Promise.resolve();
    });

    await session.recoverWithPhrase(PHRASE);

    expect(JSON.stringify(ipc.mock.calls)).not.toContain('word0');
  });

  // A commit that did not land leaves a factor the account never learned about.
  // Without the replacing write it would refuse every later mint on this device.
  it('replaces a stored factor the account never learned about', async () => {
    const session = await heldAtTheFactorPolicy();
    sdk.inputFactorKey.mockImplementation(() => {
      sdk.status = 'logged-in';
      return Promise.resolve();
    });
    sdk.commitChanges.mockRejectedValueOnce(new Error('the account could not be re-synced'));

    await expect(session.recoverWithPhrase(PHRASE)).resolves.toBeUndefined();
    expect(sdk.setDeviceFactor).toHaveBeenCalledWith('a-scalar', true);
  });

  it('refuses a phrase on a device that is not waiting for one', async () => {
    const session = createCoreKitSession(config);

    await expect(session.recoverWithPhrase(PHRASE)).rejects.toThrow('not waiting on a recovery');
    expect(sdk.inputFactorKey).not.toHaveBeenCalled();
  });
});
