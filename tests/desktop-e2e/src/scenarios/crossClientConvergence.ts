/**
 * Two instances of one vault converge: what one writes through its mount, the
 * other reads through its own.
 *
 * One secret is one vault, so both instances hold the same account on separate
 * homes and separate mounts.
 */

import { strict as assert } from 'node:assert';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { readsThrough, withInstances, type Scenario, type ScenarioContext } from '../scenario';

const SHARED_FILE = 'from-a.txt';
const SHARED_TEXT = 'a wrote this';

export const crossClientConvergence: Scenario = {
  name: 'cross-client-convergence',
  run(context: ScenarioContext) {
    return withInstances(context, ['a', 'b'], async ([a, b]) => {
      await writeFile(join(a.mountRoot, SHARED_FILE), SHARED_TEXT);

      const listed = await readsThrough(
        context,
        b,
        SHARED_FILE,
        SHARED_TEXT,
        context.deadlines.refreshMs
      );
      assert.deepEqual(listed, [SHARED_FILE], 'the second mount lists the whole vault root');

      const converged = await b.status();
      assert.equal(converged.items, 1, 'the second vault holds what the first published');
      assert.equal(converged.deadLetters, 0, 'convergence dead-letters nothing');
    });
  },
};
