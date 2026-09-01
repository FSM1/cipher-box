/**
 * The leader tab dies mid-flow, and the vault keeps its two hosts.
 *
 * A follower holds no engine; it acquires the lock the dead leader released,
 * spawns a worker and re-exports its own secret to start it
 * (blueprint/web-client.md "Failover"). The mount is the second host, and it
 * writes across the promotion: a vault that survives a leader death is one the
 * promoted tab still converges on.
 */

import { strict as assert } from 'node:assert';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { poll } from '../../../desktop-e2e/src/poll';
import { projects, type Scenario, type ScenarioContext } from '../scenario';
import { namesOf } from '../../../web-e2e/vault';

const AFTER = 'after-failover';

export const leaderFailover: Scenario = {
  name: 'leader-failover',
  async run(context: ScenarioContext) {
    const secret = context.secret();
    const mount = await context.desktop('mount', secret);
    const leader = await context.web('leader', secret);
    const follower = await leader.sibling();

    assert.equal(
      await follower.vault.reExports(),
      0,
      'a follower re-exports nothing while it waits'
    );

    await leader.page.close();
    context.log('the leader tab is gone');

    await poll(
      () => follower.vault.reExports(),
      (exports) => exports > 0,
      {
        what: 'the follower to be promoted and start its own engine',
        timeoutMs: context.deadlines.mountMs,
        intervalMs: context.deadlines.intervalMs,
      }
    );
    context.log('the follower took the lock and started its own engine');

    // A write made after the promotion, by the host that never lost its engine.
    await mkdir(join(mount.mountRoot, AFTER));
    await projects(context, mount.mountRoot, AFTER);
    await mount.refresh();

    const status = await mount.status();
    assert.equal(status.deadLetters, 0, 'the write across the failover dead-letters nothing');
    assert.equal(status.mount.state, 'mounted', 'the failover keeps the mount');

    // The promoted tab is a whole engine again: one nocache pass converges it.
    // The refusal rides the poll's last value, so a timeout says whether the
    // promotion never finished or the name never arrived.
    await poll(
      async () => {
        const refresh = await follower.vault.refreshed();
        if (!refresh.landed) return { refusal: refresh.refusal, names: [] as string[] };
        return { refusal: null, names: namesOf((await follower.vault.settled()).view) };
      },
      (seen) => seen.names.includes(AFTER),
      {
        what: `the promoted tab to converge on ${AFTER}`,
        timeoutMs: context.deadlines.refreshMs,
        intervalMs: context.deadlines.intervalMs,
      }
    );
  },
};
