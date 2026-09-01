/**
 * A write taken while the API is down publishes when the API comes back.
 *
 * The outage is real: the orchestrator owns the API process and stops it. The
 * mount must still take the write, hold it in the durable op queue, read it
 * back from the queue's own staged bytes, and publish it on the next drain that
 * reaches a live API (blueprint/desktop.md "Reads, writes, and the never-block
 * law").
 */

import { strict as assert } from 'node:assert';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  converges,
  readsBack,
  rendersItems,
  withInstances,
  type Scenario,
  type ScenarioContext,
} from '../scenario';

const OFFLINE_FILE = 'written-offline.txt';
const OFFLINE_TEXT = 'taken while the API was down';

export const offlineReplay: Scenario = {
  name: 'offline-replay',
  run(context: ScenarioContext) {
    return withInstances(context, ['a', 'b'], async ([a, b]) => {
      await context.stack.stopApi();

      await writeFile(join(a.mountRoot, OFFLINE_FILE), OFFLINE_TEXT);
      await rendersItems(context, a, 1, 'an offline write to render at its own mount');
      // The bytes are this device's own, staged and durable. Nothing about them
      // needs the API, so the writer must read them back through the outage.
      await readsBack(
        context,
        a,
        OFFLINE_FILE,
        OFFLINE_TEXT,
        'the writer to read its own file through the outage'
      );

      const held = await a.status();
      assert.equal(held.deadLetters, 0, 'an outage dead-letters nothing');

      await context.stack.startApi();

      // Only a second instance proves the publish: it never saw the queue.
      await converges(
        context,
        b,
        OFFLINE_FILE,
        OFFLINE_TEXT,
        'the second mount to serve what the outage held'
      );

      const replayed = await a.status();
      assert.equal(replayed.deadLetters, 0, 'the replay dead-letters nothing');
      assert.deepEqual(replayed.warnings, [], 'a replayed write raises no warning');
    });
  },
};
