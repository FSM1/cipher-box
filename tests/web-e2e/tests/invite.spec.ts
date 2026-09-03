/**
 * The invite link across two accounts: one vault mints, another claims, and the
 * minter converts that claim into a read grant.
 */

import { expect, test } from '../fixtures';
import { InvitePage } from '../page-objects/invite.page';
import { SharePage } from '../page-objects/share.page';
import { SharedPage } from '../page-objects/shared.page';
import { VaultPage } from '../page-objects/vault.page';
import { claim, mint } from '../sharing';

const FOLDER = 'granted-folder';

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
  const link = await mint(page, FOLDER);
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
  const link = await mint(page, FOLDER);
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
