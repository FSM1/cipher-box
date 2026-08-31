/**
 * One instance writes through its mount and reads the same bytes back.
 *
 * This is the floor the other scenarios stand on: the projection accepts a
 * write, the engine publishes it, and the mount serves it again.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  PAYLOAD,
  assert,
  settled,
  withInstances,
  type Scenario,
  type ScenarioContext,
} from '../scenario';

const FOLDER = 'round-trip';
const FILE = 'payload.txt';

export const mountRoundTrip: Scenario = {
  name: 'mount-round-trip',
  run(context: ScenarioContext) {
    return withInstances(context, ['a'], async ([a]) => {
      const folder = join(a.mountRoot, FOLDER);
      await mkdir(folder);
      await writeFile(join(folder, FILE), PAYLOAD, 'utf8');
      context.log(`wrote ${FOLDER}/${FILE} through the mount`);

      await settled(a, 1, context.deadlines);

      const status = await a.status();
      assert.equal(status.provisioned, true, 'a published vault is provisioned');
      assert.deepEqual(status.warnings, [], 'a clean round trip raises no warning');

      const readBack = await readFile(join(folder, FILE), 'utf8');
      assert.equal(readBack, PAYLOAD, 'the mount serves back the bytes it took');
    });
  },
};
