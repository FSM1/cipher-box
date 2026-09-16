/**
 * Profile: recycle bin. A delete, a restore and a purge are journaled ops, so
 * this is where the real unpin and the real reclaim answer.
 */

import { BinPage } from '../page-objects/bin.page';
import { FilesPage } from '../page-objects/files.page';
import { expect, published, signIn, test } from './fixtures';
import { filler } from './media';

const RESTORED = 'bin-restored.bin';
const PURGED = 'bin-purged.bin';

test('a deleted file restores, and a purged one does not come back', async ({ page }) => {
  const files = new FilesPage(page);
  const bin = new BinPage(page);
  await signIn(page);

  for (const name of [RESTORED, PURGED]) {
    await files.upload(name, filler(2_048));
    await expect(files.row(name)).toBeVisible({ timeout: 180_000 });
  }
  await published(page);

  for (const name of [RESTORED, PURGED]) {
    await files.remove(name);
    await expect(files.row(name)).toHaveCount(0);
  }
  await published(page);

  await bin.open();
  await bin.appeared(RESTORED);
  await bin.appeared(PURGED);
  // The vault's own retention dates every expiry on the page, so a row that
  // reads `no expiry` means the retention never landed.
  await expect(bin.retention).toBeVisible();
  await expect(bin.row(RESTORED).getByTestId('bin-expires')).not.toHaveText('no expiry');

  await bin.restore(RESTORED);
  await bin.gone(RESTORED, 180_000);
  await files.openFromSidebar();
  await expect(files.row(RESTORED)).toBeVisible({ timeout: 180_000 });
  await published(page);

  await bin.open();
  await bin.purge(PURGED);
  await bin.gone(PURGED, 180_000);
  await expect(bin.empty).toBeVisible();

  await files.openFromSidebar();
  await expect(files.row(PURGED)).toHaveCount(0);
  await expect(files.row(RESTORED)).toBeVisible();

  await page.reload();
  await expect(files.browser).toBeVisible({ timeout: 180_000 });
  await expect(files.row(RESTORED)).toBeVisible({ timeout: 180_000 });
  await expect(files.row(PURGED)).toHaveCount(0);
});
