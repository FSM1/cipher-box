/**
 * A write made at the mount while the API is away, and the tab that converges on
 * it once the API is back.
 *
 * The outage is real: the orchestrator owns the API process, so the offline op
 * queue is exercised rather than mocked.
 */

import { strict as assert } from 'node:assert';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { poll } from '../../../desktop-e2e/src/poll';
import { projects, type Scenario, type ScenarioContext } from '../scenario';
import { namesOf } from '../../../web-e2e/vault';
import type { WebHost } from '../web';

const OFFLINE = 'made-offline';

export const offlineConvergence: Scenario = {
  name: 'offline-convergence',
  async run(context: ScenarioContext) {
    const secret = context.secret();
    const mount = await context.desktop('mount', secret);
    // The second host is up before the outage, so what it converges on is the
    // write the queue carried rather than a vault it read for the first time.
    const tab = await context.web('tab', secret);

    await context.stack.stopApi();
    context.log('the API is away');

    // The mount answers the write from its own state and queues the publish:
    // an outage is not a refusal (blueprint/desktop.md "FS projection").
    await mkdir(join(mount.mountRoot, OFFLINE));
    await projects(context, mount.mountRoot, OFFLINE);

    await context.stack.startApi();
    context.log('the API is back');

    // The first pass after an outage can still land on a connection the host
    // opened while the API was away, so the barrier is a pass that lands.
    await poll(
      () => landed(mount.refresh()),
      (pass) => pass.landed,
      {
        what: 'a nocache pass at the mount to land after the outage',
        timeoutMs: context.deadlines.apiReadyMs,
        intervalMs: context.deadlines.intervalMs,
      }
    );
    await poll(
      () => mount.status(),
      (status) => status.staleness === 'fresh',
      {
        what: 'the mount to reconcile what it queued during the outage',
        timeoutMs: context.deadlines.apiReadyMs,
        intervalMs: context.deadlines.intervalMs,
      }
    );
    const drained = await mount.status();
    assert.equal(drained.deadLetters, 0, 'the queued write dead-letters nothing');

    await poll(
      () => converged(tab),
      (seen) => seen.names.includes(OFFLINE),
      {
        what: `the tab to converge on ${OFFLINE}`,
        timeoutMs: context.deadlines.apiReadyMs,
        intervalMs: context.deadlines.intervalMs,
      }
    );
  },
};

interface Pass {
  landed: boolean;
  refusal: string | null;
}

/**
 * One pass, with its refusal as a value. The refusal rides the poll's last
 * value, so a timeout names what the pass refused with rather than only that
 * time ran out.
 */
async function landed(pass: Promise<void>): Promise<Pass> {
  try {
    await pass;
    return { landed: true, refusal: null };
  } catch (error) {
    return { landed: false, refusal: error instanceof Error ? error.message : String(error) };
  }
}

async function converged(tab: WebHost): Promise<Pass & { names: string[] }> {
  const pass = await landed(tab.refresh());
  if (!pass.landed) return { ...pass, names: [] };
  const { view } = await tab.vault.settled();
  return { ...pass, names: namesOf(view) };
}
