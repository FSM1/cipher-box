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
  let release = (): void => {};
  return {
    redraws,
    restore: vi.fn(() => new Promise<void>((resolve) => (release = resolve))),
    finishRestore: (): void => release(),
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
  createLoginFlow: () => ({ methods: [], resume: () => Promise.resolve() }),
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
});
