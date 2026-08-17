import { beforeAll, describe, expect, it, vi } from 'vitest';
import type { ShellModel } from './frontDoor';

/** One snapshot per redraw; the shell mutates a single model in place. */
interface Redraw {
  phase: ShellModel['phase'];
  busy: boolean;
  step: ShellModel['step'];
}

const shell = vi.hoisted(() => {
  const redraws: Redraw[] = [];
  const vaultListeners: (() => void)[] = [];
  let release = (): void => {};
  return {
    redraws,
    vaultListeners,
    restore: vi.fn(() => new Promise<void>((resolve) => (release = resolve))),
    finishRestore: (): void => release(),
    /** The login flow's host, so a test can drive the account transitions. */
    host: null as { account: { signedIn(method: null, email: string | null): void } } | null,
    readVaultStatus: vi.fn(() => Promise.reject(new Error('no session is live'))),
    onVaultChanged: vi.fn((changed: () => void) => {
      vaultListeners.push(changed);
      return Promise.resolve(() => {});
    }),
  };
});

vi.mock('./polyfills', () => ({}));
vi.mock('./auth/facade', () => ({ shellFacade: {} }));
vi.mock('./auth/collector', () => ({ desktopCollector: () => ({}) }));
vi.mock('./auth/coreKit', () => ({ createCoreKitSession: () => ({ restore: shell.restore }) }));
vi.mock('./config', () => ({
  desktopConfig: () => ({ apiBaseUrl: 'http://api.test', googleClientId: undefined }),
}));
vi.mock('@cipherbox/login', () => ({
  createIdentityExchange: () => ({}),
  createLoginFlow: (host: never) => {
    shell.host = host;
    return { methods: [], resume: () => Promise.resolve() };
  },
}));
vi.mock('./vault', () => ({
  onVaultChanged: shell.onVaultChanged,
  readVaultStatus: shell.readVaultStatus,
}));
vi.mock('./frontDoor', () => ({
  renderShell: (_root: HTMLElement, model: ShellModel) => {
    shell.redraws.push({ phase: model.phase, busy: model.busy, step: model.step });
  },
}));

describe('the shell bootstrap', () => {
  beforeAll(async () => {
    document.body.replaceChildren(Object.assign(document.createElement('div'), { id: 'shell' }));
    await import('./main');
  });

  it('says the session is being restored while the restore is in flight', () => {
    expect(shell.restore).toHaveBeenCalled();
    expect(shell.redraws.at(-1)).toEqual({ phase: 'starting', busy: true, step: 'restore' });
  });

  it('lands at the front door once the restore settles', async () => {
    shell.finishRestore();
    await vi.waitFor(() =>
      expect(shell.redraws.at(-1)).toEqual({ phase: 'signedOut', busy: false, step: null })
    );
  });

  /**
   * Without this the window would render the snapshot it read at sign-in for
   * the life of the session, so registering the listener is not the property —
   * the listener reading again is.
   */
  it('follows the engine, rather than reading the vault once', async () => {
    expect(shell.onVaultChanged).toHaveBeenCalled();

    shell.host!.account.signedIn(null, 'member@example.com');
    await vi.waitFor(() => expect(shell.readVaultStatus).toHaveBeenCalledTimes(1));

    shell.vaultListeners.forEach((emitted) => emitted());
    await vi.waitFor(() => expect(shell.readVaultStatus).toHaveBeenCalledTimes(2));
  });
});
