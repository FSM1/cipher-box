/**
 * Two instances of one host on one vault: A writes, B reads the same bytes.
 *
 * The barrier is the nocache manual refresh, so the scenario needs no sleep and
 * no cadence luck (blueprint/testing.md, "The DX hook").
 */

import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  PAYLOAD,
  assert,
  readWhenPresent,
  settled,
  withInstances,
  type Scenario,
  type ScenarioContext,
} from '../scenario';

const FOLDER = 'cross-client';
const FILE = 'payload.txt';

export const crossClientSync: Scenario = {
  name: 'cross-client-sync',
  run(context: ScenarioContext) {
    return withInstances(context, ['a', 'b'], async ([a, b]) => {
      await mkdir(join(a.mountRoot, FOLDER));
      await writeFile(join(a.mountRoot, FOLDER, FILE), PAYLOAD, 'utf8');
      await settled(a, 1, context.deadlines);
      context.log('a published the folder and the file');

      await b.refresh();
      const readBack = await readWhenPresent(b, join(FOLDER, FILE), context.deadlines);
      assert.equal(readBack, PAYLOAD, "b's mount serves the bytes a wrote");

      const status = await b.status();
      assert.equal(status.items, 1, 'the refresh brought the root b holds up to date');
      assert.equal(status.deadLetters, 0, 'a read-only client raises no dead letter');
    });
  },
};
