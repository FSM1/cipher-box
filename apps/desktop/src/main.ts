/**
 * The shell's login bootstrap (ADR 0008 D3). Everything sequencing-shaped is
 * `@cipherbox/login`'s; this file supplies the host's own parts — the Core Kit
 * instance, the collector, the facade, and where progress and the account are
 * rendered.
 */

import './polyfills';
import { createIdentityExchange, createLoginFlow, type LoginFlow } from '@cipherbox/login';
import { desktopCollector, type DesktopCollected } from './auth/collector';
import { createCoreKitSession } from './auth/coreKit';
import { shellFacade } from './auth/facade';
import { desktopConfig } from './config';
import { renderShell, type LoginStep, type ShellActions, type ShellModel } from './frontDoor';
import { onVaultChanged, readVaultStatus } from './vault';

/** Renders an unknown throw as the one line the shell shows for it. */
function errorMessage(failure: unknown): string {
  return failure instanceof Error ? failure.message : String(failure);
}

function start(root: HTMLElement): void {
  const model: ShellModel = {
    phase: 'starting',
    busy: false,
    step: null,
    methods: [],
    email: null,
    error: null,
    codeSent: false,
    address: '',
    vault: null,
    vaultError: null,
  };

  /** Which engine the window is rendering; every transition retires the last. */
  let engineSession = 0;

  const config = desktopConfig(import.meta.env);
  const session = createCoreKitSession(config);

  const flow: LoginFlow<DesktopCollected> = createLoginFlow<DesktopCollected>({
    exchange: createIdentityExchange(config.apiBaseUrl),
    collector: desktopCollector(config.googleClientId),
    session,
    facade: shellFacade,
    // One process, one engine: there is no leader to re-export a secret to.
    secrets: null,
    account: {
      signedIn: (_method, email) => {
        model.phase = 'signedIn';
        model.email = email;
        model.codeSent = false;
        model.address = '';
        engineSession += 1;
        // This engine is not the last one, and neither is what was read off it:
        // a read that failed as the previous session ended would otherwise be
        // the first thing this one renders.
        model.vault = null;
        model.vaultError = null;
        showVault();
      },
      signedOut: () => {
        model.phase = 'signedOut';
        model.email = null;
        model.codeSent = false;
        // The engine behind them is gone, so neither outlives the session.
        engineSession += 1;
        model.vault = null;
        model.vaultError = null;
      },
    },
    progress: {
      begin: () => {
        model.busy = true;
        model.error = null;
        draw();
      },
      failed: (failure) => {
        model.error = errorMessage(failure);
      },
      end: () => {
        model.busy = false;
      },
    },
  });

  const actions: ShellActions = {
    google: () => run('google', () => flow.loginWithGoogle(undefined)),
    sendEmailCode: (email) => {
      model.address = email;
      run('emailCode', async () => {
        await flow.sendEmailCode(email);
        model.codeSent = true;
      });
    },
    submitEmailCode: (email, code) => run('signIn', () => flow.loginWithEmailCode({ email, code })),
    logout: () => run('logout', () => flow.logout()),
  };

  const draw = (): void => renderShell(root, model, actions);

  /**
   * Reads the vault the engine now holds. A read is dropped unless the session
   * it was issued against is still the live one: it otherwise describes an
   * engine this window has already left.
   *
   * One read at a time — a burst of engine events would otherwise queue a
   * snapshot build per event — with a single re-read for whatever arrived while
   * one was in flight.
   */
  let reading: Promise<void> | null = null;
  let reread = false;

  const readVault = async (): Promise<void> => {
    const issued = engineSession;
    try {
      const status = await readVaultStatus();
      if (issued !== engineSession) return;
      model.vault = status;
      model.vaultError = null;
    } catch (failure) {
      if (issued !== engineSession) return;
      model.vault = null;
      model.vaultError = errorMessage(failure);
    }
    draw();
  };

  const showVault = (): void => {
    if (reading !== null) {
      reread = true;
      return;
    }
    reading = readVault().finally(() => {
      reading = null;
      if (reread) {
        reread = false;
        showVault();
      }
    });
  };

  /** Every transition ends in a redraw, whether or not the flow refused it. */
  const run = (step: LoginStep, work: () => Promise<void>): void => {
    model.step = step;
    void work()
      .catch(() => undefined)
      .finally(() => {
        model.step = null;
        draw();
      });
  };

  model.methods = flow.methods;
  draw();

  // Re-read on every engine emit; a window that only read at sign-in would
  // show one snapshot for the life of the session.
  void onVaultChanged(() => {
    if (model.phase === 'signedIn') showVault();
  }).catch(() => undefined);

  run('restore', async () => {
    model.busy = true;
    draw();
    try {
      await session.restore();
    } finally {
      // A restore that found nothing, and one that could not run at all, both
      // leave this window at the front door rather than blank.
      if (model.phase === 'starting') model.phase = 'signedOut';
      model.busy = false;
    }
    await flow.resume();
  });
}

const root = document.getElementById('shell');
if (root === null) throw new Error('the shell window has no mount point');

try {
  start(root);
} catch (failure) {
  // A build whose login environment is unset throws before anything renders.
  root.replaceChildren();
  const failed = document.createElement('p');
  failed.className = 'error';
  failed.textContent = errorMessage(failure);
  root.append(failed);
}
