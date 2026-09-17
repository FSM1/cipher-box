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
    async ({ page, wallet }, use, testInfo) => {
      const origin = watchApiOrigin(page);
      await use(origin);
      await report(testInfo, 'account-removal', await removeOnce(page, origin(), wallet.address));
    },
    { auto: true },
  ],

  secondContext: async ({ browser }: { browser: Browser }, use, testInfo) => {
    const opened: Array<{ page: Page; apiOrigin: () => string | null; address: string }> = [];

    await use(async (privateKey?: Hex) => {
      const page = await (await browser.newContext()).newPage();
      const apiOrigin = watchApiOrigin(page);
      const wallet = await installTestWallet(page, privateKey);
      opened.push({ page, apiOrigin, address: wallet.address });
      return { page, wallet };
    });

    for (const [index, context] of opened.entries()) {
      await report(
        testInfo,
        `account-removal-${index + 1}`,
        await removeOnce(context.page, context.apiOrigin(), context.address)
      );
      await context.page.context().close();
    }
  },
});

/** The identities this worker has already taken back, as wallet addresses. */
const reclaimed = new Set<string>();

/**
 * Removes the account behind `address`, at most once per identity. Two pages
 * can hold one account — a second device signs in on the same wallet — and a
 * spec that removes explicitly still meets the automatic teardown. `DELETE
 * /account` hard-deletes the authentication rows, so a second attempt fails at
 * the refresh and reports a kept account that is in fact gone.
 */
export async function removeOnce(
  page: Page,
  apiOrigin: string | null,
  address: string
): Promise<RemovalOutcome> {
  const identity = address.toLowerCase();
  if (reclaimed.has(identity)) {
    return { removed: true, detail: 'an earlier call removed this account' };
  }
  const outcome = await removeAccount(page, apiOrigin);
  if (outcome.removed) reclaimed.add(identity);
  return outcome;
}

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
