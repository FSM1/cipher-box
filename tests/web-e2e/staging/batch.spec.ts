/**
 * Profile: batch operations. One command over several rows publishes several
 * writes, so this is where concurrent publishes meet the real name store.
 */

import { FilesPage } from '../page-objects/files.page';
import { expect, published, signIn, test } from './fixtures';
import { filler } from './media';

const FILES = ['batch-one.bin', 'batch-two.bin', 'batch-three.bin'];
const DESTINATION = 'batch-destination';

test('a batch moves, downloads and deletes every selected row', async ({ page }) => {
  const files = new FilesPage(page);
  await signIn(page);

  for (const [index, name] of FILES.entries()) {
    await files.upload(name, filler(1_024 * (index + 1)));
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

  // One download per selected file, which is the batch semantic this profile
  // owns. The bytes are not compared here: a batch save can deliver an empty
  // body, so the byte-for-byte read-back lives in the size-matrix profile,
  // which saves one file at a time.
  const downloads = await files.saveSelected(FILES.length);
  expect(downloads).toHaveLength(FILES.length);

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
