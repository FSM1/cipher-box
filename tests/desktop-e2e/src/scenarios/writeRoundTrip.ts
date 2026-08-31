/**
 * A write through the mount reaches the engine, and a name the projection
 * refuses reaches no engine and no listing.
 *
 * The mount root is the case this scenario exists for. A backend that has not
 * published its mount yet leaves that path serving the directory under it, and
 * a write there returns success and reaches nothing — silent loss, which no
 * later read can tell from an empty vault.
 */

import { strict as assert } from 'node:assert';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  refuses,
  rendersItems,
  withInstances,
  type Scenario,
  type ScenarioContext,
} from '../scenario';

/** A name `crates/fuse` classifies as platform junk on every host. */
const JUNK = '.DS_Store';

const ROOT_FILE = 'at-the-root.txt';
const FOLDER = 'folder';
const NESTED_FILE = 'nested.txt';

export const writeRoundTrip: Scenario = {
  name: 'write-round-trip',
  run(context: ScenarioContext) {
    return withInstances(context, ['a'], async ([a]) => {
      await mkdir(join(a.mountRoot, FOLDER));
      await rendersItems(context, a, 1, 'a folder made at the mount root to render a child');

      await writeFile(join(a.mountRoot, ROOT_FILE), 'at the root');
      assert.equal(
        await readFile(join(a.mountRoot, ROOT_FILE), 'utf8'),
        'at the root',
        'a file made at the mount root reads back what was written'
      );
      await rendersItems(context, a, 2, 'a file made at the mount root to render a child');

      await writeFile(join(a.mountRoot, FOLDER, NESTED_FILE), 'inside a folder');
      assert.equal(
        await readFile(join(a.mountRoot, FOLDER, NESTED_FILE), 'utf8'),
        'inside a folder',
        'a file made inside a folder reads back what was written'
      );
      // The root still holds two children: the nested file is the folder's.
      await rendersItems(context, a, 2, 'a nested file to leave the root count alone');

      await refuses(writeFile(join(a.mountRoot, JUNK), 'junk'), `the platform-junk name ${JUNK}`);
      assert.deepEqual(
        (await readdir(a.mountRoot)).sort(),
        [FOLDER, ROOT_FILE].sort(),
        'the mount lists what the vault holds, and no platform junk'
      );

      const settled = await a.status();
      assert.equal(settled.items, 2, 'the vault root holds what the mount wrote');
      assert.deepEqual(settled.warnings, [], 'a write round trip raises no warning');
    });
  },
};
