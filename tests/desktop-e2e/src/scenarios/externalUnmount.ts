/**
 * An unmount from outside the app reaches the session.
 *
 * A member ejects the vault from a terminal or Finder. The session must stop
 * naming a mount point that no longer carries the vault, and say why
 * (blueprint/desktop.md "Lifecycle").
 */

import { strict as assert } from 'node:assert';
import { poll } from '../poll';
import { isMounted, withInstances, type Scenario, type ScenarioContext } from '../scenario';

/** The words of the refusal the shell shows after an external unmount. */
const UNMOUNTED_OUTSIDE = /unmounted outside CipherBox/;

export const externalUnmount: Scenario = {
  name: 'external-unmount',
  run(context: ScenarioContext) {
    // The suite has no tool that unmounts a WinFsp mount from outside.
    if (process.platform === 'win32') {
      context.log('external-unmount: skipped, no external unmount tool on Windows');
      return Promise.resolve();
    }
    return withInstances(context, ['a'], async ([a]) => {
      await poll(
        () => isMounted(a.mountRoot),
        (mounted) => mounted,
        {
          what: 'the mount root to carry a filesystem of its own',
          timeoutMs: context.deadlines.mountMs,
          intervalMs: context.deadlines.intervalMs,
          release: () => a.abandon(),
        }
      );

      await a.unmountExternally();
      const ended = await poll(
        () => a.status(),
        (status) => status.mount.state === 'refused',
        {
          what: 'the session to report the external unmount',
          timeoutMs: context.deadlines.mountMs,
          intervalMs: context.deadlines.intervalMs,
          release: () => a.abandon(),
        }
      );
      if (ended.mount.state !== 'refused') assert.fail('the poll accepts a refusal only');
      assert.match(ended.mount.reason, UNMOUNTED_OUTSIDE);
      assert.equal(ended.deadLetters, 0, 'an unmount dead-letters nothing');
      assert.deepEqual(ended.warnings, [], 'an unmount with no write in flight owes no warning');
      assert.equal(await isMounted(a.mountRoot), false, 'the mount point carries no vault');

      await a.stop();
    });
  },
};
