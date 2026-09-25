/**
 * The invite link across two accounts: one vault mints, another previews and
 * joins it, and the minter's tick converts that claim into a read grant.
 */

import { expect, test } from '../fixtures';
import { InvitePage } from '../page-objects/invite.page';
import { SharePage } from '../page-objects/share.page';
import { SharedPage } from '../page-objects/shared.page';
import { VaultPage } from '../page-objects/vault.page';
import { claim, mint } from '../sharing';

const FOLDER = 'granted-folder';

test('@full a bare invite address carries no link and offers no join', async ({ page }) => {
  const invite = new InvitePage(page);
  const vault = new VaultPage(page);
  await page.goto('/invite');
  await vault.ready();

  await invite.expectState('waiting');
  await vault.signInHere(`solo-${crypto.randomUUID()}`);

  await invite.expectState('noLink');
  await expect(invite.joinButton).toHaveCount(0);
});

test('@full a link minted by one vault is claimed by another and converts to a grant', async ({
  page,
  browser,
}) => {
  const link = await mint(page, FOLDER);
  const share = new SharePage(page);

  const claimant = await claim(browser, link);

  await share.openUntilGranted(FOLDER, 1);

  await expect(share.permission).toHaveText('read');
  await expect(share.error).toHaveCount(0);
  await claimant.context().close();
});

test('@full a second visit to a joined link offers only "open folder"', async ({
  page,
  browser,
}) => {
  const link = await mint(page, FOLDER);
  const claimant = await claim(browser, link);

  const invite = new InvitePage(claimant);
  await invite.open(link);
  await invite.expectState('joined');
  await expect(invite.joinButton).toHaveCount(0);
  await invite.openFolderButton.click();
  await invite.expectFolderOpened();
  expect(new URL(claimant.url()).hash).toBe('');
  await claimant.context().close();
});

test("@full a join lists the folder once in the claimant's shared list", async ({
  page,
  browser,
}) => {
  const link = await mint(page, FOLDER);
  const claimant = await claim(browser, link);

  // The claimant holds the folder through the link's keys, so its list carries
  // one row for it before and after the minter converts the claim.
  const shared = new SharedPage(claimant);
  await shared.open();
  await expect(shared.rows).toHaveCount(1);
  await expect(shared.rows.getByTestId('shared-name')).toHaveText(FOLDER);
  await expect(shared.empty).toHaveCount(0);
  await expect(shared.error).toHaveCount(0);
  await claimant.context().close();
});

test('@full the preview leads with the verified folder name and lists its children', async ({
  page,
  browser,
}) => {
  const link = await mint(page, FOLDER);
  const context = await browser.newContext();
  const claimant = await context.newPage();
  const invite = new InvitePage(claimant);
  const vault = new VaultPage(claimant);
  await invite.open(link);
  await vault.ready();
  await vault.signInHere(`claimant-${crypto.randomUUID()}`);

  await invite.expectState('joinable');
  await expect(invite.headline).toHaveText(`${FOLDER} was shared with you`);
  await expect(invite.permission).toHaveText('can view');
  await expect(invite.entries).toHaveCount(0);
  await context.close();
});
