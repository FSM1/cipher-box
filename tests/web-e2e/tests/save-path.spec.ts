/**
 * The save affordance, end to end: what an ordinary browser writes to disk when
 * a member downloads a file. The round trip in `write-path.spec.ts` saves too,
 * but only to claim the bytes survive; these cases pin the route they took, the
 * name they landed under, and the tab that answered for them.
 *
 * `@full`: the byte-survival claim is already in the smoke slice's round trip,
 * and these cases each pay for a heavier setup — a multi-window transfer, and a
 * second tab — which is depth the main gate buys, not the PR gate's minutes.
 */

import { readFile } from 'node:fs/promises';
import { expect, test } from '../fixtures';
import { coldStart, drained, PAYLOAD } from '../vault';

/**
 * A space and a non-ASCII run, so the header carries a percent-encoded name
 * rather than a bare token — the browser has to decode it to land the file.
 */
const NAME = 'notes — édition 1.md';

/**
 * Past one `MEDIA_WINDOW_BYTES`, so the transfer pulls more than once and the
 * revoke that follows it has a real race to lose.
 */
const LONG = PAYLOAD.repeat(40_000);

/** Distinct names and distinct lengths, so no save can pass for another. */
const BATCH = ['batch-one.md', 'batch-two.md', 'batch-three.md'];

test('a saved file is its own bytes, not the app shell', { tag: '@full' }, async ({ page }) => {
  const { vault, files } = await coldStart(page);

  const bytes = new TextEncoder().encode(LONG);
  await files.upload(NAME, bytes);
  await expect(files.row(NAME)).toBeVisible();
  await drained(files, vault);

  const download = await files.save(NAME);

  // A `blob:` here is the buffered fallback, which works and settles nothing.
  expect(download.url()).toContain('/stream/');
  // The name rides the pipe's `content-disposition`.
  expect(download.suggestedFilename()).toBe(NAME);

  const saved = await download.path();
  expect(new Uint8Array(await readFile(saved))).toEqual(bytes);
  await expect(page.getByTestId('vault-action-error')).toHaveCount(0);
});

/**
 * The batch defect: each save used to drop its frame and withdraw its ticket in
 * the task the read settled in, while the next save navigated in that same task.
 * The browser commits a save a beat later, so one file of the batch landed empty
 * or under a name of the browser's choosing, with nothing reported.
 */
test('a batch save lands every file under its own name', { tag: '@full' }, async ({ page }) => {
  const { vault, files } = await coldStart(page);

  const sent = new Map<string, Uint8Array>();
  for (const [index, name] of BATCH.entries()) {
    const bytes = new TextEncoder().encode(PAYLOAD.repeat(index + 1));
    sent.set(name, bytes);
    await files.upload(name, bytes);
    await expect(files.row(name)).toBeVisible();
  }
  await drained(files, vault);

  for (const name of BATCH) await files.select(name);
  const downloads = await files.saveSelected(BATCH.length);

  expect(downloads.map((download) => download.suggestedFilename()).sort()).toEqual(
    [...BATCH].sort()
  );
  for (const download of downloads) {
    const name = download.suggestedFilename();
    const saved = await download.path();
    expect(new Uint8Array(await readFile(saved)), `${name} read back`).toEqual(sent.get(name));
  }
  await expect(page.getByTestId('vault-action-error')).toHaveCount(0);
});

test(
  'a save reaches the tab that minted it, whatever tab brokered last',
  { tag: '@full' },
  async ({ page }) => {
    const { vault, files } = await coldStart(page);

    const bytes = new TextEncoder().encode(PAYLOAD);
    await files.upload('shared.md', bytes);
    await expect(files.row('shared.md')).toBeVisible();
    await drained(files, vault);

    // A second tab brokers the newest port, and a save carries no client id, so
    // the pipe borrows that tab's port — whose registry minted no ticket.
    const second = await page.context().newPage();
    await second.goto('/');
    await second.waitForFunction(() => navigator.serviceWorker.controller !== null);

    const download = await files.save('shared.md');

    const saved = await download.path();
    expect(new Uint8Array(await readFile(saved))).toEqual(bytes);
    await expect(page.getByTestId('vault-action-error')).toHaveCount(0);
    await second.close();
  }
);
