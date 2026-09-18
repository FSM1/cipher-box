/**
 * A second session over a vault that already carries content: a mount that
 * restarts on the state it left, and a tab that cold-starts onto the vault the
 * mount published.
 *
 * Every other scenario brings its hosts up before the first write. This one
 * brings them up after it, which is the only way the cold-start read of a
 * populated sub-folder is exercised.
 */

import { mkdir, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  converges,
  fileBytes,
  listsAtRoot,
  listsInFolder,
  mountHeld,
  sizes,
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
    // The tab's own listing first: a write the tab never made reads at the
    // mount exactly like one the mount never received.
    await listsInFolder(context, tab, FOLDER, FROM_TAB);
    await converges(context, first, FROM_TAB, join(first.mountRoot, FOLDER));
    context.log(`both devices wrote into ${FOLDER}`);

    await first.stop();
    context.log('the first desktop instance quit');

    // The same device state, so this is the cold start of a session that finds
    // a populated cache rather than the cold start of a new device.
    const second = await context.desktop('second-mount', secret, 'mount');
    const folder = join(second.mountRoot, FOLDER);
    // The read is what puts the folder in the focus window the tick walks.
    await readdir(folder).catch(() => []);
    for (const child of [FROM_MOUNT, FROM_TAB]) {
      await converges(context, second, child, folder);
    }
    await sizes(context, second, join(folder, FROM_MOUNT), MOUNT_BYTES);
    await sizes(context, second, join(folder, FROM_TAB), TAB_BYTES);
    mountHeld(await second.status(), 'the second session');
    context.log('the second desktop instance listed both children');

    const fresh = await context.web('fresh-tab', secret);
    await listsAtRoot(context, fresh, FOLDER);
    await listsInFolder(context, fresh, FOLDER, FROM_MOUNT);
    await listsInFolder(context, fresh, FOLDER, FROM_TAB);
  },
};
