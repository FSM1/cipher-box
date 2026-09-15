/**
 * Profile: workspace build. A tree built through the real UI against the real
 * name store, then read back after a reload — so a row that never published,
 * or a publish the routing front dropped, fails here.
 */

import { FilesPage } from '../page-objects/files.page';
import { expect, published, signIn, test } from './fixtures';
import { mediaFixtures, mediaPath } from './media';

const FOLDERS = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot'];

test('a six-folder tree survives a reload', async ({ page }) => {
  const files = new FilesPage(page);
  const image = mediaFixtures().image;

  await signIn(page);

  for (const folder of FOLDERS) {
    await files.createFolder(folder);
    await expect(files.row(folder)).toBeVisible();
  }
  await published(page);

  // One folder carries a real file, so the tree read back covers a leaf as well
  // as the folders around it.
  await files.open('alpha');
  await expect(files.breadcrumbs).toContainText('alpha');
  await page.getByLabel('Choose files to upload').setInputFiles(mediaPath(image));
  await expect(files.row(image.name)).toBeVisible({ timeout: 180_000 });
  await published(page);
  await page.getByRole('button', { name: 'root', exact: true }).click();

  await files.rename('bravo', 'bravo-renamed');
  await expect(files.row('bravo-renamed')).toBeVisible();
  await published(page);

  await files.move('charlie', 'delta');
  await expect(files.row('charlie')).toHaveCount(0);
  await published(page);

  await files.remove('echo');
  await expect(files.row('echo')).toHaveCount(0);
  await published(page);

  await page.reload();
  await expect(files.browser).toBeVisible({ timeout: 180_000 });

  for (const folder of ['alpha', 'bravo-renamed', 'delta', 'foxtrot']) {
    await expect(files.row(folder)).toBeVisible({ timeout: 180_000 });
  }
  await expect(files.row('charlie')).toHaveCount(0);
  await expect(files.row('echo')).toHaveCount(0);

  await files.open('delta');
  await expect(files.row('charlie')).toBeVisible();
  await page.getByRole('button', { name: 'root', exact: true }).click();

  await files.open('alpha');
  await expect(files.row(image.name)).toBeVisible();
});
