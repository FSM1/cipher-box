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
import { renderShell, type ShellActions, type ShellModel } from './frontDoor';

/** Renders an unknown throw as the one line the shell shows for it. */
function errorMessage(failure: unknown): string {
  return failure instanceof Error ? failure.message : String(failure);
}

function start(root: HTMLElement): void {
  const model: ShellModel = {
    phase: 'starting',
    busy: false,
    methods: [],
    email: null,
    error: null,
    codeSent: false,
    address: '',
  };

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
      },
      signedOut: () => {
        model.phase = 'signedOut';
        model.email = null;
        model.codeSent = false;
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
    google: () => run(() => flow.loginWithGoogle(undefined)),
    sendEmailCode: (email) => {
      model.address = email;
      run(async () => {
        await flow.sendEmailCode(email);
        model.codeSent = true;
      });
    },
    submitEmailCode: (email, code) => run(() => flow.loginWithEmailCode({ email, code })),
    logout: () => run(() => flow.logout()),
  };

  const draw = (): void => renderShell(root, model, actions);

  /** Every transition ends in a redraw, whether or not the flow refused it. */
  const run = (step: () => Promise<void>): void => {
    void step()
      .catch(() => undefined)
      .finally(draw);
  };

  model.methods = flow.methods;
  draw();

  run(async () => {
    try {
      await session.restore();
    } finally {
      // A restore that found nothing, and one that could not run at all, both
      // leave this window at the front door rather than blank.
      if (model.phase === 'starting') model.phase = 'signedOut';
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
