/**
 * A file across the two clients: the bytes, the size and the mtime.
 *
 * The folder scenarios prove a name crosses. A size and an mtime need the
 * child's own record, which the parent's listing does not carry
 * (`Deadlines.convergeMs`), so only a file exercises that leg.
 */

import { strict as assert } from 'node:assert';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { poll } from '../../../desktop-e2e/src/poll';
import { fileBytes, listsAtRoot, mountHeld, projects } from '../scenario';
import type { Scenario, ScenarioContext } from '../scenario';
import type { WebHost } from '../web';

const FOLDER = 'round-trip';
const FROM_MOUNT = 'from-the-mount.bin';
const FROM_TAB = 'from-the-tab.bin';
/** Byte counts the listing renders as one whole label, so it names an exact one. */
const MOUNT_BYTES = 1536;
const MOUNT_SIZE = '1.5 KB';
const TAB_BYTES = 2048;

/** The read the mount owes, as the value a failed wait reports. */
const SAME_BYTES = 'the bytes the tab uploaded';

export const fileRoundTrip: Scenario = {
  name: 'file-round-trip',
  async run(context: ScenarioContext) {
    const secret = context.secret();
    const mount = await context.desktop('mount', secret);
    // The tab joins the vault while it is still empty. A tab that cold-starts
    // onto a vault the mount already published is what `second-session` covers.
    const tab = await context.web('tab', secret);

    const folderAtMount = join(mount.mountRoot, FOLDER);
    const written = fileBytes(MOUNT_BYTES);
    const from = Date.now();
    await mkdir(folderAtMount);
    await writeFile(join(folderAtMount, FROM_MOUNT), written);
    const to = Date.now();
    await mount.refresh();
    context.log(`the mount wrote ${FROM_MOUNT} in ${FOLDER}`);

    await listsAtRoot(context, tab, FOLDER);
    const cells = await rendered(context, tab, FOLDER, FROM_MOUNT, MOUNT_SIZE);
    const window = await tab.files.renderedDays([from, to]);
    assert.ok(
      window.includes(cells.modified),
      `the tab renders ${FROM_MOUNT} modified ${cells.modified}, and the mount wrote it on ` +
        window.join(' or ')
    );
    context.log(`the tab rendered ${FROM_MOUNT} at ${cells.size}, modified ${cells.modified}`);

    await tab.openFiles();
    await tab.files.open(FOLDER);
    await served(tab, FROM_MOUNT, written);
    context.log(`the tab served ${FROM_MOUNT} as the mount wrote it`);

    const uploaded = fileBytes(TAB_BYTES);
    await tab.files.upload(FROM_TAB, uploaded);
    await tab.vault.settled();
    context.log(`the tab uploaded ${FROM_TAB} into ${FOLDER}`);

    await mount.refresh();
    await projects(context, mount, FROM_TAB, folderAtMount);
    const atMount = join(folderAtMount, FROM_TAB);
    await poll(
      async () => {
        await mount.refresh();
        return readBack(atMount, uploaded);
      },
      (seen) => seen === SAME_BYTES,
      {
        what: `the mount to read back ${FROM_TAB} as the tab uploaded it`,
        timeoutMs: context.deadlines.convergeMs,
        intervalMs: context.deadlines.readIntervalMs,
        release: () => mount.abandon(),
      }
    );
    assert.equal(
      (await stat(atMount)).size,
      TAB_BYTES,
      `the mount sizes ${FROM_TAB} at what the tab uploaded`
    );

    mountHeld(await mount.status(), 'the file round trip');
  },
};

/**
 * Reads one listed file back through the tab's own save path. A size cell
 * carries the child's record; only the saved bytes carry its content.
 */
async function served(host: WebHost, name: string, want: Uint8Array): Promise<void> {
  const saved = await (await host.files.save(name)).path();
  const bytes = await readFile(saved);
  assert.ok(
    bytes.equals(Buffer.from(want)),
    `the tab saves ${name} as ${want.length} bytes, and it saved ${bytes.length}`
  );
}

/** What the mount serves for `path`, as one short value a timeout can name. */
async function readBack(path: string, want: Uint8Array): Promise<string> {
  try {
    const bytes = await readFile(path);
    return bytes.equals(Buffer.from(want)) ? SAME_BYTES : `${bytes.length} other bytes`;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code ?? String(error);
  }
}

/**
 * Polls until one fresh pass renders `name` in `folder` at `size`. A row the
 * listing has named but not resolved paints `...`, which this never accepts.
 */
function rendered(
  context: ScenarioContext,
  host: WebHost,
  folder: string,
  name: string,
  size: string
): Promise<{ size: string; modified: string }> {
  const absent = { size: '(no row)', modified: '(no row)' };
  return poll(
    async () => {
      // Each pass re-enters the folder: the focus window is what the sync tick
      // walks, and it is the folder that carries the children under test.
      await host.openFiles();
      await host.files.open(folder);
      await host.refresh();
      if ((await host.files.row(name).count()) !== 1) return absent;
      return host.files.cells(name);
    },
    (seen) => seen.size === size,
    {
      what: `a pass at ${host.name} to render ${name} at ${size} in ${folder}`,
      timeoutMs: context.deadlines.convergeMs,
      intervalMs: context.deadlines.intervalMs,
    }
  );
}
