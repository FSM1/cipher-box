/**
 * The settings route, and the origin-wide session end its device actions drive.
 *
 * The cross-tab specs open a second *page in the same context*: that is what
 * shares an origin's `BroadcastChannel` and `navigator.locks`, which is the wire
 * the session end rides (`packages/client/src/broadcast.ts`). Two browser
 * contexts would share neither and could not see the defect at all.
 */

import type { Page } from '@playwright/test';
import { expect, test } from '../fixtures';
import { FilesPage } from '../page-objects/files.page';
import { LoginPage } from '../page-objects/login.page';
import { SettingsPage } from '../page-objects/settings.page';
import { VaultPage } from '../page-objects/vault.page';
import { coldStart } from '../vault';

/** A second tab of the same origin, signed in on the same vault as a follower. */
async function sibling(page: Page, accountId: string): Promise<VaultPage> {
  const tab = await page.context().newPage();
  const vault = new VaultPage(tab);
  await vault.open();
  await vault.joinAs(accountId);
  await expect(new FilesPage(tab).browser).toBeVisible();
  return vault;
}

test('@full a byo endpoint round-trips through the settings save', async ({ page }) => {
  await coldStart(page);
  const settings = new SettingsPage(page);
  await settings.open();

  await settings.setPinMode('dual');
  await settings.setProvider('https://ipfs.example');
  await settings.save();

  await expect(settings.savedMark).toBeVisible();
  await expect(settings.saveError).toHaveCount(0);
});

test('@full the engine refuses an endpoint it will not talk to, in its own words', async ({
  page,
}) => {
  await coldStart(page);
  const settings = new SettingsPage(page);
  await settings.open();

  // Plaintext to a non-loopback host, which `validate_byo_config` refuses.
  await settings.setProvider('http://ipfs.example');
  await settings.save();

  await expect(settings.saveError).toBeVisible();
  await expect(settings.savedMark).toHaveCount(0);
});

test('forgetting the device signs every tab out and re-seeds none', async ({ page }) => {
  const { vault, accountId } = await coldStart(page);
  const other = await sibling(page, accountId);
  const settings = new SettingsPage(page);
  await settings.open();
  // Reached through the sidebar, so this is also the route's own smoke check.
  await expect(page).toHaveURL(/\/settings$/);
  await expect(settings.accountId).toHaveText(accountId);

  await settings.forgetDevice();

  // The tab that asked is signed out — and so is the one that did not, which
  // would otherwise win the released engine lock and cold-start over the state
  // the erase just wiped.
  await expect(page).toHaveURL(/\/$/);
  await expect(other.page).toHaveURL(/\/$/);
  await expect(new LoginPage(other.page).googleButton).toBeVisible();
  await expect(new FilesPage(other.page).browser).toHaveCount(0);

  // The load-bearing half: no promotion re-exported a secret to start a
  // replacement engine with, in either tab.
  expect(await other.reExports()).toBe(0);
  expect(await vault.reExports()).toBe(0);
});

test('signing out ends the session in a sibling tab too', async ({ page }) => {
  const { vault, files, accountId } = await coldStart(page);
  const other = await sibling(page, accountId);

  await files.signOut();

  await expect(page).toHaveURL(/\/$/);
  await expect(other.page).toHaveURL(/\/$/);
  expect(await other.reExports()).toBe(0);
  expect(await vault.reExports()).toBe(0);
});
