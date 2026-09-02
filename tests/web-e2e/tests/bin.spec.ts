/**
 * The `/bin` route. A cold-started vault keeps the documented retention, so a
 * delete is soft: this gates the route, its sidebar link, the entry landing in
 * the bin, the restore putting it back in the browser, and the purge taking it
 * away for good.
 *
 * A restore and a purge are journaled ops, so each one changes the published
 * index only after the queue drains. Every case therefore settles the queue and
 * then re-reads, exactly as a member does.
 *
 * `@full`: each case pays for a cold start plus two settled publishes, which
 * the bounded smoke slice has no room for.
 */

import { expect, test } from '../fixtures';
import { BinPage } from '../page-objects/bin.page';
import { SettingsPage } from '../page-objects/settings.page';
import { coldStart, drained } from '../vault';

test('@full a fresh vault reads an empty bin, not a missing one', async ({ page }) => {
  await coldStart(page);
  const bin = new BinPage(page);

  await bin.open();

  // The record exists from vault genesis, so its own existence says nothing
  // about what the account deleted (blueprint/engine.md "An empty bin is the
  // bottom rung"). The page therefore reads an empty bin, never a missing one.
  await expect(bin.empty).toBeVisible();
  await expect(bin.unestablished).toHaveCount(0);
  await expect(bin.error).toHaveCount(0);
  // The retention is the vault's own; the page never invents a figure.
  await expect(bin.retention).toBeVisible();

  await bin.readAgain();

  await expect(bin.empty).toBeVisible();
  await expect(bin.error).toHaveCount(0);
});

test('@full a deleted folder lands in the bin, and a restore returns it', async ({ page }) => {
  const { vault, files } = await coldStart(page);
  const bin = new BinPage(page);

  await files.createFolder('reports');
  await vault.settled();
  await files.remove('reports');
  expect(await drained(files, vault)).not.toContain('folder reports');

  await bin.open();
  await expect(bin.row('reports')).toBeVisible();
  await expect(bin.error).toHaveCount(0);

  await bin.restore('reports');
  await bin.gone('reports');
  await expect(bin.empty).toBeVisible();

  // Through the sidebar: this suite's session is in-memory, so a document load
  // would land the tab back on the front door.
  await page.getByTestId('nav-item-files').click();
  expect(await drained(files, vault)).toContain('folder reports');
});

test('@full a purge takes the entry off the bin for good', async ({ page }) => {
  const { vault, files } = await coldStart(page);
  const bin = new BinPage(page);

  await files.createFolder('drafts');
  await vault.settled();
  await files.remove('drafts');
  await drained(files, vault);

  await bin.open();
  await expect(bin.row('drafts')).toBeVisible();

  await bin.purge('drafts');
  await bin.gone('drafts');

  await expect(bin.empty).toBeVisible();
  await expect(bin.error).toHaveCount(0);
});

test('@full a retention of 0 saved on the form makes the next delete a hard delete', async ({
  page,
}) => {
  const { vault, files } = await coldStart(page);
  const settings = new SettingsPage(page);
  const bin = new BinPage(page);

  await settings.open();
  await settings.binRetention.fill('0');
  await settings.save();
  await expect(settings.savedMark).toBeVisible();
  await expect(settings.saveError).toHaveCount(0);

  await files.openFromSidebar();
  await files.createFolder('drafts');
  await vault.settled();
  await files.remove('drafts');
  expect(await drained(files, vault)).not.toContain('folder drafts');

  await bin.open();

  await expect(bin.retention).toHaveAttribute('data-days', '0');
  // The page lists no row at all. A name-filtered absence would also hold for a
  // row locator that can match nothing, and prove nothing.
  await expect(bin.rows).toHaveCount(0);
  await expect(bin.error).toHaveCount(0);
});
