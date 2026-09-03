/**
 * The two halves of a share, shared by the specs that need one: the owner mints
 * a link on a folder, and a second account spends it.
 */

import type { Browser, Page } from '@playwright/test';
import { expect } from './fixtures';
import { InvitePage } from './page-objects/invite.page';
import { SharePage } from './page-objects/share.page';
import { VaultPage } from './page-objects/vault.page';
import { coldStart } from './vault';

/** Cold-starts a vault, publishes `folder`, and mints a link on it. */
export async function mint(page: Page, folder: string): Promise<URL> {
  const { files, vault } = await coldStart(page);
  await files.createFolder(folder);
  await vault.settled();
  const share = new SharePage(page);
  await share.open(folder);
  const link = await share.mintLink();
  await share.close();
  return link;
}

/**
 * Spends `link` under a second account, in its own browser context.
 *
 * A second page of the owner's context would share the origin's
 * `BroadcastChannel` and `navigator.locks`, which is what makes two tabs one
 * session — and a claim has to come from a second account, not a second tab.
 * The claim route must also survive a tab that holds no session: the fragment is
 * the capability, so it has to outlive the sign-in.
 */
export async function claim(browser: Browser, link: URL): Promise<Page> {
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
