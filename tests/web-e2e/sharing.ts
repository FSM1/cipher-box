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

/** How a claimant takes a session, which is the only leg a caller varies. */
export interface ClaimSignIn {
  /** The account the claim is spent under. The panel must name it. */
  account: string;
  /** Starts a session in the tab, which is already on the claim route. */
  start(): Promise<void>;
}

/**
 * Spends `link` in `page`.
 *
 * The claim route must survive a tab that holds no session: the fragment is the
 * capability, so it has to outlive the sign-in.
 */
export async function claimHere(page: Page, link: URL, how: ClaimSignIn): Promise<void> {
  const invite = new InvitePage(page);
  const vault = new VaultPage(page);

  await invite.open(link);
  await invite.expectState('waiting');
  await expect(invite.recheck).toBeVisible();
  await expect(invite.confirm).toHaveCount(0);

  await vault.ready();
  await how.start();

  await invite.expectState('ready');
  await expect(invite.account).toContainText(how.account);
  await invite.claim();
  await invite.expectState('claimed');
  // The claim takes the capability out of the address, so a reload cannot spend
  // it a second time.
  expect(new URL(page.url()).hash).toBe('');
}

/**
 * Spends `link` under a second account of its own, in its own browser context.
 *
 * A second page of the owner's context would share the origin's
 * `BroadcastChannel` and `navigator.locks`, which is what makes two tabs one
 * session — and a claim has to come from a second account, not a second tab.
 */
export async function claim(browser: Browser, link: URL): Promise<Page> {
  const context = await browser.newContext();
  const page = await context.newPage();
  const account = `claimant-${crypto.randomUUID()}`;
  await claimHere(page, link, {
    account,
    start: () => new VaultPage(page).signInHere(account),
  });
  return page;
}
