/**
 * The staging fixtures. Every page carries its own test wallet, so a spec that
 * opens a second context gets a second account without asking.
 */

import { test as base, expect, type Page } from '@playwright/test';
import { FilesPage } from '../page-objects/files.page';
import { LoginPage } from '../page-objects/login.page';
import { installTestWallet, TEST_WALLET_NAME, type TestWallet } from './wallet';

export { expect } from '@playwright/test';

export const test = base.extend<{ wallet: TestWallet }>({
  // Automatic: a page that reached the front door without one has no shipped
  // method left to sign in with.
  wallet: [
    async ({ page }, use) => {
      await use(await installTestWallet(page));
    },
    { auto: true },
  ],
});

/**
 * Signs in through the shipped wallet method and waits for the vault browser.
 * Returns the milliseconds the whole journey took, which is what the timing
 * profile records.
 */
export async function signIn(page: Page): Promise<number> {
  const login = new LoginPage(page);
  const files = new FilesPage(page);

  await page.goto('/');
  await expect(login.walletButton).toBeEnabled({ timeout: 60_000 });

  const started = Date.now();
  await login.walletButton.click();
  await page.getByRole('button', { name: `Connect with ${TEST_WALLET_NAME}`, exact: true }).click();

  await page.waitForURL('**/files', { timeout: 180_000 });
  await expect(files.browser).toBeVisible({ timeout: 120_000 });
  return Date.now() - started;
}

/**
 * Waits until the listing carries no unpublished row — the hookless stand-in
 * for the local suite's drained queue, since the chrome marks a row until its
 * write publishes. A dead-lettered row fails here rather than at whatever read
 * used it.
 */
export async function published(page: Page): Promise<void> {
  const browser = new FilesPage(page).browser;
  await expect(browser.locator('.file-list-item-status--dead')).toHaveCount(0);
  await expect(browser.locator('.file-list-item-status')).toHaveCount(0, { timeout: 180_000 });
}
