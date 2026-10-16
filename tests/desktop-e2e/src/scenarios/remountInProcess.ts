/**
 * A sign-out and a sign-in remount the vault in the same process, after an
 * external unmount.
 *
 * The `ENDED` refusal tells the member to sign out and back in, with no
 * restart. On macOS each mount runs its own FUSE-T server, and an unmount does
 * not end it, so the scenario also proves that the detach and the sign-out end
 * the server of their mount.
 */

import { strict as assert } from 'node:assert';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Instance } from '../instance';
import { poll } from '../poll';
import {
  isMounted,
  readsBack,
  withInstances,
  type Scenario,
  type ScenarioContext,
  unmountAndAwaitRefusal,
} from '../scenario';

const FILE = 'after-the-remount.txt';
const TEXT = 'served after the remount';

/** The FUSE-T servers `instance` runs: one for each live mount, on macOS only. */
async function servers(instance: Instance): Promise<number[]> {
  return (await instance.children())
    .filter((child) => !child.zombie && child.command.endsWith('go-nfsv4'))
    .map((child) => child.pid);
}

/** Waits until the process table lists none of `ended`, a zombie included. */
async function serversEnd(
  context: ScenarioContext,
  instance: Instance,
  ended: number[],
  what: string
): Promise<void> {
  await poll(
    () => instance.children(),
    (children) => !children.some((child) => ended.includes(child.pid)),
    {
      what: `${instance.name}: ${what}`,
      timeoutMs: context.deadlines.shutdownMs,
      intervalMs: context.deadlines.intervalMs,
      release: () => instance.abandon(),
    }
  );
}

export const remountInProcess: Scenario = {
  name: 'remount-in-process',
  async run(context: ScenarioContext) {
    if (process.platform === 'win32') {
      context.log('remount-in-process: skipped, no external unmount tool on Windows');
      return;
    }
    const macOS = process.platform === 'darwin';
    await withInstances(context, ['a'], async ([a]) => {
      const ejected = await servers(a);
      if (macOS) assert.equal(ejected.length, 1, 'a live mount runs one FUSE-T server');

      await unmountAndAwaitRefusal(context, a);
      await serversEnd(context, a, ejected, 'the detach to end the server of the ejected mount');

      await a.signOut();
      await a.signIn();
      await writeFile(join(a.mountRoot, FILE), TEXT);
      await readsBack(context, a, FILE, TEXT, 'the mount after the sign-in to serve a file');
      const remounted = await servers(a);
      if (macOS) {
        assert.equal(remounted.length, 1, 'the remount runs one FUSE-T server');
        assert.ok(!ejected.includes(remounted[0]), 'the remount runs a server of its own');
      }

      await a.signOut();
      await serversEnd(context, a, remounted, 'the sign-out to end the server of its mount');
      assert.equal(await isMounted(a.mountRoot), false, 'the sign-out unmounts the vault');
    });
  },
};
