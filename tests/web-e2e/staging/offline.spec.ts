/**
 * Profile: offline queue. A write made with the network cut stays marked until
 * the network returns, and the publish that clears the mark is read off the
 * routing front rather than off the chrome alone.
 */

import { FilesPage } from '../page-objects/files.page';
import { expect, published, signIn, test } from './fixtures';
import { routingOrigin, watchRoutingFront } from './frontContract';

const QUEUED = 'queued-while-offline';

test('a write made offline publishes when the network returns', async ({ page, baseURL }) => {
  const files = new FilesPage(page);
  await signIn(page);

  await files.createFolder('before-the-cut');
  await expect(files.row('before-the-cut')).toBeVisible();
  await published(page);

  await page.context().setOffline(true);

  await files.createFolder(QUEUED);
  await expect(files.row(QUEUED)).toBeVisible();
  await expect(files.row(QUEUED).locator('.file-list-item-status')).toBeVisible();
  await expect(files.row(QUEUED).locator('.file-list-item-status--dead')).toHaveCount(0);

  // Watched from the reconnect on, so the publish this asserts is the queued
  // write draining rather than an attempt the cut already refused.
  const log = watchRoutingFront(page, routingOrigin(baseURL!));
  await page.context().setOffline(false);
  await files.status.click();
  await published(page);

  expect(log.publishes.length, 'the reconnect published the queued write').toBeGreaterThan(0);

  await page.reload();
  await expect(files.browser).toBeVisible({ timeout: 180_000 });
  await expect(files.row(QUEUED)).toBeVisible({ timeout: 180_000 });
});
