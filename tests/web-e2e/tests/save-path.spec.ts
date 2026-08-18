/**
 * The save affordance, end to end: what an ordinary browser writes to disk when
 * a member downloads a file. It is the one claim the round trip in
 * `write-path.spec.ts` cannot make — that one reads back through the preview,
 * because the buffered read and the saved file are different paths and only
 * this one leaves the tab.
 */

import { readFile } from 'node:fs/promises';
import { expect, test } from '../fixtures';
import { coldStart, drained, PAYLOAD } from './vault';

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

test('a saved file is its own bytes, not the app shell', async ({ page }) => {
  const { vault, files } = await coldStart(page);

  // The pipe serves the save, so a tab the worker does not control would prove
  // nothing: the buffered fallback would answer and it is not the path at risk.
  await expect
    .poll(() => page.evaluate(() => navigator.serviceWorker.controller !== null))
    .toBe(true);

  const bytes = new TextEncoder().encode(LONG);
  await files.upload(NAME, bytes);
  await expect(files.row(NAME)).toBeVisible();
  expect(await drained(files, vault)).toEqual([`file ${NAME}`]);

  const download = await files.save(NAME);

  // A `blob:` here is the buffered fallback, which works and settles nothing.
  expect(download.url()).toContain('/stream/');
  // The name rides the pipe's `content-disposition`; a link's `download`
  // attribute cannot carry it, because a link never reaches the worker.
  expect(download.suggestedFilename()).toBe(NAME);

  const saved = await download.path();
  expect(new Uint8Array(await readFile(saved))).toEqual(bytes);
  await expect(page.getByTestId('vault-action-error')).toHaveCount(0);
});

test('a save reaches the tab that minted it, whatever tab brokered last', async ({ page }) => {
  const { vault, files } = await coldStart(page);

  const bytes = new TextEncoder().encode(PAYLOAD);
  await files.upload('shared.md', bytes);
  await expect(files.row('shared.md')).toBeVisible();
  expect(await drained(files, vault)).toEqual(['file shared.md']);

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
});
