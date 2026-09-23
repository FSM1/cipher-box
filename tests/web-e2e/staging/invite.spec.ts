/**
 * Profile: invite link. A link minted on a folder, spent by a second identity
 * through the real claim route behind the front, and converted into the grant
 * that link stands for.
 */

import { FilesPage } from '../page-objects/files.page';
import { InvitePage } from '../page-objects/invite.page';
import { SharePage } from '../page-objects/share.page';
import { SharedPage } from '../page-objects/shared.page';
import { expect, published, signIn, test } from './fixtures';

// The claim has to cross a second identity's sync pass against the real record
// plane, which outlasts the suite's own per-test budget on a 2-vCPU box.
test.setTimeout(900_000);

const FOLDER = 'invited';

test('a minted link is claimed by a second identity and converted to a grant', async ({
  page,
  secondContext,
}) => {
  const files = new FilesPage(page);
  await signIn(page);
  await files.createFolder(FOLDER);
  await expect(files.row(FOLDER)).toBeVisible();
  await published(page);

  const share = new SharePage(page);
  await share.open(FOLDER);
  await share.permissionChoice.selectOption('read');
  const link = await share.mintLink('30 days');
  await share.close();

  const { page: claimant } = await secondContext();
  await signIn(claimant);

  const invite = new InvitePage(claimant);
  await invite.open(link);
  await invite.expectState('ready', 180_000);
  await expect(invite.account).not.toBeEmpty();
  await invite.claim();
  await invite.expectState('claimed', 180_000);
  // The claim takes the capability out of the address, so a reload cannot spend
  // it a second time.
  expect(new URL(claimant.url()).hash).toBe('');
  await claimant.getByRole('link', { name: 'go to your files' }).click();

  // A claim is a standing request; the grant is what the owner converts it to.
  await share.open(FOLDER);
  await expect(share.convertClaimsButton).toBeEnabled({ timeout: 180_000 });
  await share.convertClaimsButton.click();
  await expect(share.grantRows).toHaveCount(1, { timeout: 180_000 });
  await expect(share.permission).toHaveText('read');
  await share.close();

  const list = new SharedPage(claimant);
  await list.open();
  await list.awaitStanding('granted', 600_000);
  await list.rows.getByTestId('shared-open').click();
  await expect(new FilesPage(claimant).breadcrumbs).toBeVisible({ timeout: 180_000 });
});
