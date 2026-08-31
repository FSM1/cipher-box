/**
 * The invite link across two accounts: one vault mints, another claims, and the
 * minter converts that claim into a read grant.
 *
 * The claimant runs in its own browser context. A second page of the owner's
 * context would share the origin's `BroadcastChannel` and `navigator.locks`,
 * which is what makes two tabs one session — and a claim has to come from a
 * second account, not a second tab.
 */

import type { Browser, Page } from '@playwright/test';
import { expect, test } from '../fixtures';
import { InvitePage } from '../page-objects/invite.page';
import { SharePage } from '../page-objects/share.page';
import { SharedPage } from '../page-objects/shared.page';
import { VaultPage } from '../page-objects/vault.page';
import { coldStart } from '../vault';

const FOLDER = 'granted-folder';

async function mint(page: Page): Promise<URL> {
  const { files, vault } = await coldStart(page);
  await files.createFolder(FOLDER);
  await vault.settled();
  const share = new SharePage(page);
  await share.open(FOLDER);
  const link = await share.mintLink();
  await share.close();
  return link;
}

/**
 * The claim route must survive a tab that holds no session: the fragment is the
 * capability, so it has to outlive the sign-in.
 */
async function claim(browser: Browser, link: URL): Promise<Page> {
  const context = await browser.newContext();
  const page = await context.newPage();
  const invite = new InvitePage(page);
  const vault = new VaultPage(page);

  await invite.open(link);
  await invite.expectState('waiting');
  await expect(invite.recheck).toBeVisible();
  await expect(invite.confirm).toHaveCount(0);

  await vault.ready();
  const account = `claimant-${crypto.randomUUID()}`;
  await vault.signInHere(account);

  await invite.expectState('ready');
  await expect(invite.account).toContainText(account);
  await invite.claim();
  await invite.expectState('claimed');
  // The claim takes the capability out of the address, so a reload cannot spend
  // it a second time.
  expect(new URL(page.url()).hash).toBe('');
  return page;
}

test('@full a bare claim address carries no link and offers no claim', async ({ page }) => {
  const invite = new InvitePage(page);
  const vault = new VaultPage(page);
  await page.goto('/invite');
  await vault.ready();

  await invite.expectState('waiting');
  await vault.signInHere(`solo-${crypto.randomUUID()}`);

  await invite.expectState('noLink');
  await expect(invite.confirm).toHaveCount(0);
});

test('@full a link minted by one vault is claimed by another and converts to a grant', async ({
  page,
  browser,
}) => {
  const link = await mint(page);
  const share = new SharePage(page);

  const claimant = await claim(browser, link);

  // A claim reaches the minter's inbox and asks for a grant; the grant itself
  // is the minter's to complete, so nothing is granted until this is pressed.
  await share.open(FOLDER);
  await expect(share.noGrants).toBeVisible();
  await share.convertClaimsButton.click();

  await expect(share.grantRows).toHaveCount(1);
  await expect(share.permission).toHaveText('read');
  await expect(share.error).toHaveCount(0);
  await claimant.context().close();
});

test('@full a claim on its own grants nothing, and leaves the claimant on its own vault', async ({
  page,
  browser,
}) => {
  const link = await mint(page);
  const claimant = await claim(browser, link);

  await claimant.getByRole('link', { name: 'go to your files' }).click();
  await expect(claimant).toHaveURL(/\/files$/);

  // The minter has converted nothing, so the claim has asked for access and
  // carries none — which is the promise the claimed copy makes.
  const shared = new SharedPage(claimant);
  await shared.open();
  await expect(shared.empty).toBeVisible();
  await expect(shared.error).toHaveCount(0);
  await claimant.context().close();
});
