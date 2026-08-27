import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { IdentityCredential } from '@cipherbox/login';
import { invoke } from '@tauri-apps/api/core';
import type { DesktopConfig } from '../config';
import { createCoreKitSession } from './coreKit';

/** What the SDK is handed as its store, and what the shell put behind it. */
interface CoreKitStorage {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  purge(): Promise<void>;
}

const sdk = vi.hoisted(() => ({
  status: 'logged-in',
  storage: null as CoreKitStorage | null,
  logout: vi.fn((): Promise<void> => Promise.resolve()),
  loginWithJWT: vi.fn((): Promise<void> => Promise.resolve()),
}));

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@toruslabs/tss-dkls-lib', () => ({ tssLib: {} }));
vi.mock('@cipherbox/login', () => ({
  accountIdFromTssPoint: () => 'an-account-id',
  isIdentityMethod: (method: unknown) => method === 'google',
}));
vi.mock('@web3auth/mpc-core-kit', () => ({
  COREKIT_STATUS: { LOGGED_IN: 'logged-in' },
  WEB3AUTH_NETWORK: { MAINNET: 'mainnet', DEVNET: 'devnet' },
  Web3AuthMPCCoreKit: class {
    constructor(options: { storage: CoreKitStorage }) {
      sdk.storage = options.storage;
    }
    get status(): string {
      return sdk.status;
    }
    init = (): Promise<void> => Promise.resolve();
    loginWithJWT = sdk.loginWithJWT;
    commitChanges = (): Promise<void> => Promise.resolve();
    logout = sdk.logout;
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

beforeEach(() => {
  ipc.mockReset();
  ipc.mockResolvedValue(null);
  sdk.logout.mockClear();
  sdk.loginWithJWT.mockClear();
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

  // A partial session must not stay resident: this device holds no factor, so
  // what the login left behind opens nothing and only waits to be taken.
  it('leaves nothing of a login that still needs a recovery phrase', async () => {
    sdk.status = 'needs-a-share';
    const session = createCoreKitSession(config);

    await expect(session.login(credential)).rejects.toThrow('recovery phrase');
    expect(ipc).toHaveBeenCalledWith('core_kit_purge');
  });

  // What the partial sign-in left behind is a device factor, so a caller told
  // only to find a recovery phrase would never learn it is still on the disk.
  it('says so when a partial login could not be cleared, and still names the phrase', async () => {
    sdk.status = 'needs-a-share';
    const session = createCoreKitSession(config);
    ipc.mockRejectedValue(new Error('the keyring is locked'));

    await expect(session.login(credential)).rejects.toThrow(
      /recovery phrase[\s\S]*the keyring is locked/
    );
  });
});
