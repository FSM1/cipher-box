/**
 * The mount across one session, end to end.
 *
 * The shell starts headless on a dev key, mints the vault, projects it as a
 * filesystem, answers a manual refresh, and gives the mount back on `quit`
 * (blueprint/desktop.md "Lifecycle"). Every later scenario stands on this one.
 */

import { strict as assert } from 'node:assert';
import { readdir, stat } from 'node:fs/promises';
import { withInstances, type Scenario, type ScenarioContext } from '../scenario';

export const mountLifecycle: Scenario = {
  name: 'mount-lifecycle',
  run(context: ScenarioContext) {
    return withInstances(context, ['a'], async ([a]) => {
      // `startInstance` already waited for `mounted`, so the mount point is a
      // real directory by the time this body runs.
      const mounted = await stat(a.mountRoot);
      assert.equal(mounted.isDirectory(), true, 'the mount point is a directory');

      const started = await a.status();
      assert.equal(started.provisioned, true, 'a cold start mints the vault');
      assert.equal(started.deadLetters, 0, 'a cold start dead-letters nothing');
      assert.deepEqual(started.warnings, [], 'a cold start raises no warning');
      assert.equal(started.mount.state, 'mounted', 'the session projects the vault');

      // The nocache manual refresh reads past every cache, so it refuses on a
      // record plane it cannot reach rather than answering from a snapshot.
      await a.refresh();
      const refreshed = await a.status();
      assert.equal(refreshed.mount.state, 'mounted', 'a refresh keeps the mount');
      assert.equal(refreshed.deadLetters, 0, 'a refresh dead-letters nothing');
      assert.deepEqual(refreshed.warnings, [], 'a refresh against a live stack raises no warning');

      // `stop` quits over the control endpoint, which is the orderly path:
      // quiesce the adapter, unmount, then end the engine.
      await a.stop();
      const left = await readdir(a.mountRoot).catch(() => []);
      assert.deepEqual(left, [], 'the mount point holds nothing once the session ends');
    });
  },
};
