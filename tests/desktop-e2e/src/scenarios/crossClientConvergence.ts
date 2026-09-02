/**
 * Two mounts of one vault converge on what either of them writes.
 *
 * The network is the only thing between them: each instance runs its own home,
 * its own engine and its own mount, and neither reads the other's disk. So a
 * name and its bytes reach the second mount only after the first one publishes
 * them and the second one resolves them.
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

const FROM_A = 'from-a.txt';
const TEXT_A = 'written on a';
const FROM_B = 'from-b.txt';
const TEXT_B = 'written on b';

export const crossClientConvergence: Scenario = {
  name: 'cross-client-convergence',
  run(context: ScenarioContext) {
    return withInstances(context, ['a', 'b'], async ([a, b]) => {
      await writeFile(join(a.mountRoot, FROM_A), TEXT_A);
      await rendersItems(context, a, 1, 'the write to render at its own mount');
      await readsBack(context, a, FROM_A, TEXT_A, 'the writer to read its own file');

      await converges(context, b, FROM_A, TEXT_A, 'the second mount to serve from-a.txt');

      // The other direction, over the same pair: convergence must not depend on
      // which instance minted the vault.
      await writeFile(join(b.mountRoot, FROM_B), TEXT_B);
      await rendersItems(context, b, 2, 'the second write to render at its own mount');
      await converges(context, a, FROM_B, TEXT_B, 'the first mount to serve from-b.txt');

      for (const instance of [a, b]) {
        const settled = await instance.status();
        assert.equal(settled.items, 2, `${instance.name} holds both files`);
        assert.equal(settled.deadLetters, 0, `${instance.name} dead-lettered nothing`);
        assert.deepEqual(settled.warnings, [], `${instance.name} raised no warning`);
      }
    });
  },
};
