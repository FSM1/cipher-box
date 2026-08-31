/**
 * Two instances of one host on one vault: A writes, B reads the same bytes.
 *
 * This scenario proves the publication. B holds its own engine, and its nocache
 * manual refresh reads the network rather than A. So the bytes B serves can
 * only come from what A published (blueprint/testing.md, "The DX hook").
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

const FOLDER = 'cross-client';
const FILE = 'payload.txt';

export const crossClientSync: Scenario = {
  name: 'cross-client-sync',
  run(context: ScenarioContext) {
    return withInstances(context, ['a', 'b'], async ([a, b]) => {
      await mkdir(join(a.mountRoot, FOLDER));
      await writeFile(join(a.mountRoot, FOLDER, FILE), PAYLOAD, 'utf8');
      await rendered(a, 1, context.deadlines);
      context.log('a took the folder and the file through its mount');

      await b.refresh();
      const readBack = await readWhenPresent(b, join(FOLDER, FILE), context.deadlines);
      assert.equal(
        readBack,
        PAYLOAD,
        'b resolved with nocache and read the bytes a published, so a published them'
      );

      const status = await b.status();
      assert.equal(status.items, 1, 'the nocache refresh brought the root b renders up to date');
      assert.equal(status.deadLetters, 0, 'a read-only client raises no dead letter');
    });
  },
};
