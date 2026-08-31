/**
 * A write through the mount while the API is away is taken, journaled, and
 * replayed once the API returns.
 *
 * The outage is real: the orchestrator owns the API process and stops it. The
 * never-block law says the mount answers throughout, and the durable op queue
 * says nothing the mount accepted is lost.
 */

import { strict as assert } from 'node:assert';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  readsThrough,
  rendersItems,
  withInstances,
  type Scenario,
  type ScenarioContext,
} from '../scenario';

const QUEUED_FILE = 'written-offline.txt';
const QUEUED_TEXT = 'written while the API was away';

export const offlineReplay: Scenario = {
  name: 'offline-replay',
  run(context: ScenarioContext) {
    return withInstances(context, ['a', 'b'], async ([a, b]) => {
      await context.stack.stopApi();

      await writeFile(join(a.mountRoot, QUEUED_FILE), QUEUED_TEXT);
      assert.equal(
        await readFile(join(a.mountRoot, QUEUED_FILE), 'utf8'),
        QUEUED_TEXT,
        'the mount serves what it took while the API was away'
      );
      const queued = await rendersItems(context, a, 1, 'the offline write to render');
      assert.equal(queued.deadLetters, 0, 'a write taken while offline is journaled, not lost');

      await context.stack.startApi();

      const listed = await readsThrough(
        context,
        b,
        QUEUED_FILE,
        QUEUED_TEXT,
        context.deadlines.scenarioMs / 2
      );
      assert.deepEqual(listed, [QUEUED_FILE], 'the replayed op is the whole vault root');

      const replayed = await a.status();
      assert.equal(replayed.deadLetters, 0, 'a replayed op dead-letters nothing');
    });
  },
};
