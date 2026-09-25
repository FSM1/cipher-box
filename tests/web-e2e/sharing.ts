/**
 * The two halves of a share, shared by the specs that need one: the owner mints
 * a link on a folder and a second account spends it, or the two accounts
 * exchange contact codes and the owner grants the folder.
 */

import type { Browser, BrowserContext, Page } from '@playwright/test';
import { expect } from './fixtures';
import type { FilesPage } from './page-objects/files.page';
import { InvitePage } from './page-objects/invite.page';
import { SharePage } from './page-objects/share.page';
import { SharedPage } from './page-objects/shared.page';
import { VaultPage } from './page-objects/vault.page';
import { coldStart, nodeOf } from './vault';

/** The recipient's own folder, whose share dialog carries the contact import. */
const RECIPIENT_FOLDER = 'recipient-own';

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
 * Spends `link` in `page`: sign-in, the preview, then the join.
 *
 * The invite route must survive a tab that holds no session: the fragment is
 * the capability, so it has to outlive the sign-in.
 */
export async function claimHere(page: Page, link: URL, how: ClaimSignIn): Promise<void> {
  const invite = new InvitePage(page);
  const vault = new VaultPage(page);

  await invite.open(link);
  await invite.expectState('waiting');
  await expect(invite.signIn).toBeVisible();
  await expect(invite.joinButton).toHaveCount(0);

  await vault.ready();
  await how.start();

  await invite.expectState('joinable');
  await expect(invite.account).toContainText(how.account);
  await invite.join();
  await invite.expectFolderOpened();
  // The join takes the capability out of the address, so a reload cannot spend
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

/** Both sides of a grant made by a hand exchange of contact codes. */
export interface CodeGrant {
  readonly owner: VaultPage;
  readonly ownerFiles: FilesPage;
  readonly recipient: VaultPage;
  readonly recipientPage: Page;
  readonly recipientFiles: FilesPage;
  readonly recipientContext: BrowserContext;
  /** The granted folder's node id, as the `/shared` row carries it. */
  readonly scope: string;
}

/**
 * Cold-starts two accounts that exchange contact codes by hand, grants `folder`
 * of the first to the second at `permission`, and waits until the recipient's
 * `/shared` row reads the grant.
 *
 * The recipient gets its own browser context: a second page of the owner's
 * context shares the origin's `BroadcastChannel` and `navigator.locks` and is
 * therefore the same session.
 */
export async function grantByCode(
  page: Page,
  browser: Browser,
  folder: string,
  permission: 'read' | 'write'
): Promise<CodeGrant> {
  const { files: ownerFiles, vault: owner } = await coldStart(page);
  await ownerFiles.createFolder(folder);
  const scope = nodeOf((await owner.settled()).view, folder);

  const ownerShare = new SharePage(page);
  await ownerShare.open(folder);
  const ownerCode = await ownerShare.readOwnContactCode();

  const recipientContext = await browser.newContext();
  const recipientPage = await recipientContext.newPage();
  const { files: recipientFiles, vault: recipient } = await coldStart(recipientPage);
  await recipientFiles.createFolder(RECIPIENT_FOLDER);
  await recipient.settled();
  const recipientShare = new SharePage(recipientPage);
  await recipientShare.open(RECIPIENT_FOLDER);
  await recipientShare.importContact(ownerCode);
  const recipientCode = await recipientShare.readOwnContactCode();
  await recipientShare.close();

  await ownerShare.grantTo(recipientCode, permission);
  await ownerShare.close();

  // The recipient's mailbox leg rides the nocache pass, so one refresh both
  // accepts the delivered pointer and classifies it.
  await recipient.refresh();
  const shared = new SharedPage(recipientPage);
  await shared.open();
  await shared.readStanding(scope, 'granted');
  const row = shared.row(scope);
  await expect(row).toHaveCount(1);
  await expect(row.getByTestId('shared-permission')).toHaveText(permission);
  await expect(shared.error).toHaveCount(0);

  return { owner, ownerFiles, recipient, recipientPage, recipientFiles, recipientContext, scope };
}
