/**
 * Every conflict the mount renders, on one instance.
 *
 * The FS core renders an outcome and never merges (blueprint/desktop.md), so
 * each check reads an errno or a listing rather than a race. The add/add
 * rebase rules belong to the engine simulation harness, which owns them
 * deterministically.
 */

import { mkdir, readFile, readdir, rename, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  PAYLOAD,
  assert,
  refusedWith,
  settled,
  withInstances,
  type Scenario,
  type ScenarioContext,
} from '../scenario';

const FOLDER = 'conflicts';
/** One name in NFC. Its NFD twin decomposes the accented letter. */
const COMPOSED = 'édition'.normalize('NFC');
const DECOMPOSED = COMPOSED.normalize('NFD');
const JUNK = '.DS_Store';
const KEPT = 'report';

export const conflictOutcome: Scenario = {
  name: 'conflict-outcomes-at-the-mount',
  run(context: ScenarioContext) {
    return withInstances(context, ['a'], async ([a]) => {
      const root = join(a.mountRoot, FOLDER);
      await mkdir(root);
      await mkdir(join(root, KEPT));
      await mkdir(join(root, COMPOSED));

      await refusedWith('EEXIST', `a second ${KEPT}`, () => mkdir(join(root, KEPT)));

      await refusedWith('EEXIST', `${KEPT} in upper case`, () =>
        mkdir(join(root, KEPT.toUpperCase()))
      );

      await refusedWith('EEXIST', 'the decomposed twin of a composed name', () =>
        mkdir(join(root, DECOMPOSED))
      );

      await refusedWith('EINVAL', `the platform-junk name ${JUNK}`, () =>
        writeFile(join(root, JUNK), 'junk', 'utf8')
      );

      // A rename over a file that exists is atomic: no reader sees it half done.
      const source = join(root, 'source.txt');
      const destination = join(root, 'destination.txt');
      await writeFile(destination, 'the bytes the rename replaces', 'utf8');
      await writeFile(source, PAYLOAD, 'utf8');
      await rename(source, destination);

      assert.equal(
        await readFile(destination, 'utf8'),
        PAYLOAD,
        'the replaced destination holds the source bytes'
      );
      await refusedWith('ENOENT', 'the renamed source path', () => stat(source));

      const listed = (await readdir(root)).map((name) => name.normalize('NFC')).sort();
      assert.deepEqual(
        listed,
        [COMPOSED, KEPT, 'destination.txt'].sort(),
        'the folder lists one entry per name, and no junk'
      );

      await settled(a, 1, context.deadlines);
    });
  },
};
