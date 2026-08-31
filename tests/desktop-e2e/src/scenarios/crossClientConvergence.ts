/**
 * Two instances of one vault converge: what one writes through its mount, the
 * other reads through its own.
 *
 * One secret is one vault, so both instances hold the same account on separate
 * homes and separate mounts. The second instance is the only proof of a
 * publish: the first renders its own pending ops whether or not they left the
 * device.
 */

import { strict as assert } from 'node:assert';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { poll } from '../poll';
import { withInstances, type Scenario, type ScenarioContext } from '../scenario';

const SHARED_FILE = 'from-a.txt';
const SHARED_TEXT = 'a wrote this';

export const crossClientConvergence: Scenario = {
  name: 'cross-client-convergence',
  run(context: ScenarioContext) {
    return withInstances(context, ['a', 'b'], async ([a, b]) => {
      await writeFile(join(a.mountRoot, SHARED_FILE), SHARED_TEXT);

      // Each read re-resolves: the manual refresh reads past every cache, and
      // the listing that follows it is the one the mount answers from.
      const listed = await poll(
        async () => {
          await b.refresh();
          return readdir(b.mountRoot);
        },
        (names) => names.includes(SHARED_FILE),
        {
          what: `${b.name}: the mount to list what ${a.name} wrote`,
          timeoutMs: context.deadlines.refreshMs,
          intervalMs: context.deadlines.intervalMs,
        }
      );
      assert.deepEqual(listed, [SHARED_FILE], 'the second mount lists the whole vault root');

      assert.equal(
        await readFile(join(b.mountRoot, SHARED_FILE), 'utf8'),
        SHARED_TEXT,
        'the second mount reads the content the first published'
      );

      const converged = await b.status();
      assert.equal(converged.items, 1, 'the second vault holds what the first published');
      assert.equal(converged.deadLetters, 0, 'convergence dead-letters nothing');
    });
  },
};
