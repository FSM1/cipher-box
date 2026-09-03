/**
 * The PR gate's one cross-client scenario: two clients on one shared scope, with
 * the nocache manual refresh as the only barrier between them.
 *
 * This is the timing-profile slice the merge-blocking budget holds
 * (blueprint/testing.md "CI gates"). The whole cross-client matrix — a browser
 * beside a mounted desktop — runs in `tests/cross-client`, which needs a mount
 * and therefore a runner this gate does not have.
 */

import { expect, test } from '../fixtures';
import { SharePage } from '../page-objects/share.page';
import { SharedPage } from '../page-objects/shared.page';
import { VaultPage } from '../page-objects/vault.page';
import { claim, mint } from '../sharing';
import { nodeOf } from '../vault';

const FOLDER = 'crossed-folder';

test('a grant reaches the second client on one nocache refresh', async ({ page, browser }) => {
  const link = await mint(page, FOLDER);
  const owner = new VaultPage(page);
  const share = new SharePage(page);
  const scope = nodeOf((await owner.settled()).view, FOLDER);

  const claimant = await claim(browser, link);
  await share.open(FOLDER);
  await share.convertClaimsButton.click();
  await expect(share.grantRows).toHaveCount(1);
  await share.close();

  // The recipient's mailbox leg rides the nocache pass, so one refresh both
  // accepts the delivered share and classifies it. Nothing here waits on the
  // poll cadence, and nothing sleeps.
  const grantee = new VaultPage(claimant);
  const shared = new SharedPage(claimant);
  await claimant.getByRole('link', { name: 'go to your files' }).click();
  await grantee.refresh();

  await shared.open();
  await shared.readAgain();
  const row = shared.row(scope);
  await expect(row).toHaveCount(1);
  await expect(row.getByTestId('shared-standing')).toHaveAttribute('data-resolution', 'granted');
  await expect(shared.error).toHaveCount(0);

  await claimant.context().close();
});
