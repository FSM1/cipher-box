import { beforeAll, describe, expect, it, vi } from 'vitest';
import type { ShellActions, ShellModel } from './frontDoor';
import type { VaultStatus } from './vault';

/** One snapshot per redraw; the shell mutates a single model in place. */
interface Redraw {
  phase: ShellModel['phase'];
  busy: boolean;
  step: ShellModel['step'];
}

/** Stands in for the shared package's own class, which this file mocks away. */
const { RecoveryRequired } = vi.hoisted(() => ({
  RecoveryRequired: class RecoveryRequiredError extends Error {
    constructor() {
      super('this device needs your recovery phrase before it can sign in');
      this.name = 'RecoveryRequiredError';
    }
  },
}));

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
    /** The last actions the window rendered, so a test can drive them. */
    actions: null as ShellActions | null,
    loginWithGoogle: vi.fn((): Promise<void> => Promise.resolve()),
    recoverWithPhrase: vi.fn((): Promise<void> => Promise.resolve()),
    /** Whether the Core Kit session still holds a login at the factor policy. */
    awaitsRecovery: vi.fn((): boolean => true),
    readVaultStatus: vi.fn(
      (): Promise<VaultStatus> => Promise.reject(new Error('no session is live'))
    ),
    invoke: vi.fn((): Promise<void> => Promise.resolve()),
    onVaultChanged: vi.fn((changed: () => void) => {
      vaultListeners.push(changed);
      return Promise.resolve(() => {});
    }),
  };
});

vi.mock('./polyfills', () => ({}));
vi.mock('./auth/facade', () => ({ shellFacade: {} }));
vi.mock('./auth/collector', () => ({ desktopCollector: () => ({}) }));
vi.mock('./auth/coreKit', () => ({
  createCoreKitSession: () => ({
    restore: shell.restore,
    awaitsRecovery: shell.awaitsRecovery,
  }),
}));
vi.mock('./config', () => ({
  desktopConfig: () => ({ apiBaseUrl: 'http://api.test', googleClientId: undefined }),
}));
vi.mock('@cipherbox/login', () => ({
  RecoveryRequiredError: RecoveryRequired,
  createIdentityExchange: () => ({}),
  createLoginFlow: (host: never) => {
    shell.host = host;
    return {
      methods: [],
      resume: () => Promise.resolve(),
      loginWithGoogle: shell.loginWithGoogle,
      recoverWithPhrase: shell.recoverWithPhrase,
    };
  },
}));
vi.mock('./vault', () => ({
  onVaultChanged: shell.onVaultChanged,
  readVaultStatus: shell.readVaultStatus,
}));
// `./window` stays real, so this file drives the visibility rule the shell
// runs rather than a stand-in for it.
vi.mock('@tauri-apps/api/core', () => ({ invoke: shell.invoke }));
vi.mock('./frontDoor', () => ({
  renderShell: (_root: HTMLElement, model: ShellModel, actions: ShellActions) => {
    shell.actions = actions;
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
    // A device with a session to resume is owed the menu bar, so nothing asks
    // for the window until the restore has said whether there is one.
    expect(shell.invoke).not.toHaveBeenCalled();
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

  /**
   * The shell lives in the menu bar: the window is chrome the member is shown
   * while the session needs them, and taken away once the vault is mounted.
   */
  it('shows the window at the front door and hides it once the vault mounted', async () => {
    expect(shell.invoke).toHaveBeenCalledWith('set_main_window_visible', { visible: true });

    shell.readVaultStatus.mockResolvedValue({
      items: 0,
      staleness: 'fresh',
      deadLetters: 0,
      provisioned: true,
      warnings: [],
      mount: { state: 'mounted', path: '/home/member/CipherBox' },
    });
    shell.vaultListeners.forEach((emitted) => emitted());

    await vi.waitFor(() =>
      expect(shell.invoke).toHaveBeenCalledWith('set_main_window_visible', { visible: false })
    );
  });

  /**
   * A login held at the factor policy is a transition, not a failure: the copy
   * on this window promises the recovery phrase works here, so the shell owes
   * the member a field to type it into (ADR 0009 D2).
   */
  it('shows the phrase prompt when a sign-in stops at the factor policy', async () => {
    shell.loginWithGoogle.mockRejectedValueOnce(new RecoveryRequired());

    shell.actions!.google();

    await vi.waitFor(() => expect(shell.redraws.at(-1)?.phase).toBe('recovery'));
  });

  it('keeps the prompt when the phrase itself did not open the account', async () => {
    shell.loginWithGoogle.mockRejectedValueOnce(new RecoveryRequired());
    shell.actions!.google();
    await vi.waitFor(() => expect(shell.redraws.at(-1)?.phase).toBe('recovery'));

    shell.recoverWithPhrase.mockRejectedValueOnce(new Error('that phrase did not open it'));
    const drawn = shell.redraws.length;

    void shell.actions!.submitRecoveryPhrase('a typed recovery phrase').catch(() => undefined);

    await vi.waitFor(() => expect(shell.redraws.length).toBeGreaterThan(drawn));
    expect(shell.redraws.at(-1)?.phase).toBe('recovery');
  });

  /**
   * The shared flow ends the Core Kit session when the engine refuses the secret
   * it exported. A prompt left standing over that ended login refuses every
   * phrase typed into it after.
   */
  it('returns to the front door when a refused handoff ended the held login', async () => {
    shell.awaitsRecovery.mockReturnValue(false);
    shell.recoverWithPhrase.mockRejectedValueOnce(new Error('the engine refused the secret'));

    void shell.actions!.submitRecoveryPhrase('a typed recovery phrase').catch(() => undefined);

    await vi.waitFor(() => expect(shell.redraws.at(-1)?.phase).toBe('signedOut'));
  });
});
