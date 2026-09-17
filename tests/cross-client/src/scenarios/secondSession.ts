/**
 * A second session over a vault that already carries content: a mount that
 * restarts on the state it left, and a tab that cold-starts onto the vault the
 * mount published.
 *
 * Every other scenario brings its hosts up before the first write. This one
 * brings them up after it, which is the only way the cold-start read of a
 * populated sub-folder is exercised.
 */

import { strict as assert } from 'node:assert';
import { mkdir, readdir, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  fileBytes,
  listsAtRoot,
  listsInFolder,
  mountHeld,
  projects,
  type Scenario,
  type ScenarioContext,
} from '../scenario';

const FOLDER = 'both-devices';
const FROM_MOUNT = 'by-the-mount.bin';
const FROM_TAB = 'by-the-tab.bin';
const MOUNT_BYTES = 1536;
const TAB_BYTES = 2048;

export const secondSession: Scenario = {
  name: 'second-session',
  async run(context: ScenarioContext) {
    const secret = context.secret();
    const first = await context.desktop('mount', secret);
    const tab = await context.web('tab', secret);

    await mkdir(join(first.mountRoot, FOLDER));
    await writeFile(join(first.mountRoot, FOLDER, FROM_MOUNT), fileBytes(MOUNT_BYTES));
    await first.refresh();
    await listsAtRoot(context, tab, FOLDER);

    await tab.files.open(FOLDER);
    await tab.files.upload(FROM_TAB, fileBytes(TAB_BYTES));
    await tab.vault.settled();
    await first.refresh();
    await projects(context, first, FROM_TAB, join(first.mountRoot, FOLDER));
    context.log(`both devices wrote into ${FOLDER}`);

    await first.stop();
    context.log('the first desktop instance quit');

    // The same device state, so this is the cold start of a session that finds
    // a populated cache rather than the cold start of a new device.
    const second = await context.desktop('second-mount', secret, 'mount');
    const folder = join(second.mountRoot, FOLDER);
    // The read is what puts the folder in the focus window the tick walks.
    await readdir(folder).catch(() => []);
    await second.refresh();
    for (const child of [FROM_MOUNT, FROM_TAB]) {
      await projects(context, second, child, folder);
    }
    assert.equal(
      (await stat(join(folder, FROM_MOUNT))).size,
      MOUNT_BYTES,
      `the second session sizes ${FROM_MOUNT} at what the first one wrote`
    );
    assert.equal(
      (await stat(join(folder, FROM_TAB))).size,
      TAB_BYTES,
      `the second session sizes ${FROM_TAB} at what the tab uploaded`
    );
    mountHeld(await second.status(), 'the second session');
    context.log('the second desktop instance listed both children');

    const fresh = await context.web('fresh-tab', secret);
    await listsAtRoot(context, fresh, FOLDER);
    await listsInFolder(context, fresh, FOLDER, FROM_MOUNT);
    await listsInFolder(context, fresh, FOLDER, FROM_TAB);
  },
};
