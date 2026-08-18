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

test('a saved file is its own bytes, not the app shell', async ({ page }) => {
  const { vault, files } = await coldStart(page);

  // The pipe serves the save, so a tab the worker does not control would prove
  // nothing: the buffered fallback would answer and it is not the path at risk.
  await expect
    .poll(() => page.evaluate(() => navigator.serviceWorker.controller !== null))
    .toBe(true);

  const bytes = new TextEncoder().encode(PAYLOAD);
  await files.upload('notes.md', bytes);
  await expect(files.row('notes.md')).toBeVisible();
  expect(await drained(files, vault)).toEqual(['file notes.md']);

  const download = await files.save('notes.md');

  // A `blob:` here is the buffered fallback, which works and settles nothing.
  expect(download.url()).toContain('/stream/');
  // The name rides the pipe's `content-disposition`; a link's `download`
  // attribute cannot carry it, because a link never reaches the worker.
  expect(download.suggestedFilename()).toBe('notes.md');

  const saved = await download.path();
  expect(new Uint8Array(await readFile(saved))).toEqual(bytes);
  await expect(page.getByTestId('vault-action-error')).toHaveCount(0);
});
