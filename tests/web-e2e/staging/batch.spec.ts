/**
 * Profile: batch operations. One command over several rows publishes several
 * writes, so this is where concurrent publishes meet the real name store.
 */

import { readFile } from 'node:fs/promises';
import { FilesPage } from '../page-objects/files.page';
import { expect, published, signIn, test } from './fixtures';
import { filler } from './media';

const FILES = ['batch-one.bin', 'batch-two.bin', 'batch-three.bin'];
const DESTINATION = 'batch-destination';

test('a batch moves, downloads and deletes every selected row', async ({ page }) => {
  const files = new FilesPage(page);
  await signIn(page);

  const sent = new Map<string, Uint8Array>();
  for (const [index, name] of FILES.entries()) {
    const bytes = filler(1_024 * (index + 1));
    sent.set(name, bytes);
    await files.upload(name, bytes);
    await expect(files.row(name)).toBeVisible({ timeout: 180_000 });
  }
  await files.createFolder(DESTINATION);
  await published(page);

  // Select-all covers the folder as well, which is the selection that offers
  // no download; the count names what the bar acts on.
  await files.selectAll();
  await expect(files.selectionCount).toHaveText('3 files, 1 folder selected');
  await files.selectAll();
  await expect(files.selectionBar).toHaveCount(0);

  for (const name of FILES) await files.select(name);
  await expect(files.selectionCount).toHaveText('3 files selected');

  // Matched on the bytes, not on the name: a save that streams through the
  // service worker names the download after the stored name, which is not the
  // name the listing shows.
  const downloads = await files.saveSelected(FILES.length);
  const saved: Uint8Array[] = [];
  for (const download of downloads) {
    saved.push(new Uint8Array(await readFile(await download.path())));
  }
  const bySize = (left: Uint8Array, right: Uint8Array) => left.length - right.length;
  expect(saved.sort(bySize)).toEqual([...sent.values()].sort(bySize));

  await files.moveSelected(DESTINATION);
  for (const name of FILES) await expect(files.row(name)).toHaveCount(0);
  await published(page);

  await files.open(DESTINATION);
  for (const name of FILES) await expect(files.row(name)).toBeVisible({ timeout: 180_000 });

  await files.selectAll();
  await files.removeSelected();
  for (const name of FILES) await expect(files.row(name)).toHaveCount(0);
  await published(page);
  await expect(files.emptyState).toBeVisible();
  await expect(page.getByTestId('vault-action-error')).toHaveCount(0);
});
