/**
 * A write survives a real outage and reaches the other instance.
 *
 * The orchestrator owns the API, so the outage is the API stopped rather than a
 * mock. The write is journaled, so the mount acks it while nothing can publish.
 * B's read after the API returns is what proves the replay.
 */

import { strict as assert } from 'node:assert';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  PAYLOAD,
  readWhenPresent,
  rendered,
  withInstances,
  type Scenario,
  type ScenarioContext,
} from '../scenario';

const FOLDER = 'offline';
const FILE = 'queued.txt';

export const offlineReplay: Scenario = {
  name: 'offline-replay',
  run(context: ScenarioContext) {
    return withInstances(context, ['a', 'b'], async ([a, b]) => {
      await context.stack.stopApi();
      context.log('the API is down; the outage is real');

      await mkdir(join(a.mountRoot, FOLDER));
      await writeFile(join(a.mountRoot, FOLDER, FILE), PAYLOAD, 'utf8');
      context.log('the mount acked the write while nothing could publish');

      const offline = await a.waitFor(
        'the staleness ladder to reach offline',
        (status) => status.staleness === 'offline',
        context.deadlines.offlineMs
      );
      assert.equal(offline.deadLetters, 0, 'an outage journals a write; it never dead-letters it');

      await context.stack.startApi();
      context.log('the API is back');

      await a.refresh();
      await rendered(a, 1, context.deadlines);

      await b.refresh();
      const readBack = await readWhenPresent(b, join(FOLDER, FILE), context.deadlines);
      assert.equal(
        readBack,
        PAYLOAD,
        'b resolved with nocache and read the journaled write, so the replay published it'
      );

      for (const instance of [a, b]) {
        const status = await instance.status();
        assert.equal(status.deadLetters, 0, `${instance.name} carries no dead letter`);
      }
    });
  },
};
