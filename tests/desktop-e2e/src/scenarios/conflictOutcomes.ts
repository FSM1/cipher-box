/**
 * What the projection renders when a filesystem call conflicts with the vault
 * it already holds.
 *
 * Each call here must reach the caller as an error and leave the vault as it
 * was. The error number a host reports is its own translation of the
 * projection's refusal, so this scenario asserts the refusal and the state, not
 * the number.
 */

import { strict as assert } from 'node:assert';
import { mkdir, readdir, rmdir, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  refuses,
  rendersItems,
  withInstances,
  type Scenario,
  type ScenarioContext,
} from '../scenario';

const FOLDER = 'folder';
const CHILD = 'child.txt';
/** Past `MAX_NAME_BYTES`, which the projection refuses on every host. */
const TOO_LONG = 'n'.repeat(300);

export const conflictOutcomes: Scenario = {
  name: 'conflict-outcomes',
  run(context: ScenarioContext) {
    return withInstances(context, ['a'], async ([a]) => {
      const root = a.mountRoot;
      await mkdir(join(root, FOLDER));
      await writeFile(join(root, FOLDER, CHILD), 'held');
      await rendersItems(context, a, 1, 'the seeded folder to render');

      const taken = await refuses(mkdir(join(root, FOLDER)), 'a folder over a name already taken');
      assert.equal(taken.code, 'EEXIST', 'a name already in the vault is reported as taken');

      await refuses(rmdir(join(root, FOLDER)), 'removing a folder that still holds a child');
      await refuses(unlink(join(root, FOLDER)), 'unlinking a folder as though it were a file');
      await refuses(rmdir(join(root, FOLDER, CHILD)), 'removing a file as though it were a folder');
      await refuses(
        writeFile(join(root, TOO_LONG), 'too long'),
        'a name past the length the vault holds'
      );
      await refuses(mkdir(join(root, FOLDER, CHILD, 'under')), 'a folder under a file');

      assert.deepEqual(
        await readdir(root),
        [FOLDER],
        'a refused call leaves the mount root as it was'
      );
      assert.deepEqual(
        await readdir(join(root, FOLDER)),
        [CHILD],
        'a refused call leaves the folder as it was'
      );

      const settled = await a.status();
      assert.equal(settled.items, 1, 'no refused call reached the vault');
      assert.equal(settled.deadLetters, 0, 'a refusal is not a dead letter');
    });
  },
};
