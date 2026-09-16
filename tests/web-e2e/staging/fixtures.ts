/**
 * The staging fixtures. Every page carries its own test wallet, so a spec that
 * opens a second context gets a second account without asking, and every
 * account a spec mints is removed when the spec ends.
 */

import { test as base, expect, type Browser, type Page } from '@playwright/test';
import type { Hex } from 'viem';
import { FilesPage } from '../page-objects/files.page';
import { LoginPage } from '../page-objects/login.page';
import { removeAccount, watchApiOrigin, type RemovalOutcome } from './cleanup';
import { installTestWallet, TEST_WALLET_NAME, type TestWallet } from './wallet';

export { expect } from '@playwright/test';

/** A page in its own browser context, with the wallet it signs in under. */
export interface SecondContext {
  readonly page: Page;
  readonly wallet: TestWallet;
}

/**
 * Opens a browser context of its own. A second page of the first context would
 * share the origin's `BroadcastChannel` and `navigator.locks`, which is what
 * makes two tabs one session.
 *
 * Passing `privateKey` signs the new context in as the SAME identity subject,
 * which is a second device rather than a second account.
 */
export type OpenSecondContext = (privateKey?: Hex) => Promise<SecondContext>;

interface StagingFixtures {
  wallet: TestWallet;
  /** The API origin this tab reached, once an authentication call named one. */
  apiOrigin: () => string | null;
  secondContext: OpenSecondContext;
}

export const test = base.extend<StagingFixtures>({
  // Automatic: a page that reached the front door without one has no shipped
  // method left to sign in with.
  wallet: [
    async ({ page }, use) => {
      await use(await installTestWallet(page));
    },
    { auto: true },
  ],

  // Automatic: staging keeps whatever a run leaves behind, and nothing else
  // reclaims it. The removal is reported, never asserted — a spec fails on its
  // own subject, and `account-removal.spec.ts` is what holds the path itself
  // to a verdict.
  apiOrigin: [
    async ({ page }, use, testInfo) => {
      const origin = watchApiOrigin(page);
      await use(origin);
      await report(testInfo, 'account-removal', await removeAccount(page, origin()));
    },
    { auto: true },
  ],

  secondContext: async ({ browser }: { browser: Browser }, use, testInfo) => {
    const opened: Array<{ page: Page; apiOrigin: () => string | null }> = [];

    await use(async (privateKey?: Hex) => {
      const page = await (await browser.newContext()).newPage();
      const apiOrigin = watchApiOrigin(page);
      const wallet = await installTestWallet(page, privateKey);
      opened.push({ page, apiOrigin });
      return { page, wallet };
    });

    for (const [index, context] of opened.entries()) {
      await report(
        testInfo,
        `account-removal-${index + 1}`,
        await removeAccount(context.page, context.apiOrigin())
      );
      await context.page.context().close();
    }
  },
});

function report(
  testInfo: {
    attach: (name: string, options: { body: string; contentType: string }) => Promise<void>;
  },
  label: string,
  outcome: RemovalOutcome
): Promise<void> {
  return testInfo.attach(label, {
    body: `${outcome.removed ? 'removed' : 'kept'}: ${outcome.detail}`,
    contentType: 'text/plain',
  });
}

/**
 * Signs in through the shipped wallet method and waits for the vault browser.
 * Returns the milliseconds the whole journey took, which is what the timing
 * profile records.
 */
export async function signIn(page: Page): Promise<number> {
  const files = new FilesPage(page);

  const started = await connectWallet(page);
  await page.waitForURL('**/files', { timeout: 180_000 });
  await expect(files.browser).toBeVisible({ timeout: 120_000 });
  return Date.now() - started;
}

/**
 * Drives the wallet method as far as the signature, and no further: a browser
 * that holds no factor for this identity stops at the recovery choice rather
 * than at the vault. Returns the instant the journey started.
 */
export async function connectWallet(page: Page): Promise<number> {
  const login = new LoginPage(page);
  await page.goto('/');
  await expect(login.walletButton).toBeEnabled({ timeout: 60_000 });

  const started = Date.now();
  await login.walletButton.click();
  await page.getByRole('button', { name: `Connect with ${TEST_WALLET_NAME}`, exact: true }).click();
  return started;
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
