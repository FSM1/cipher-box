/**
 * Profile: sharing and revoke. A second real account, a grant that propagates
 * through the real record plane, and a cut the recipient sees. It also records
 * the share leg of the journey baseline, because the second identity is here.
 */

import { FilesPage } from '../page-objects/files.page';
import { SharedPage } from '../page-objects/shared.page';
import { expect, published, test } from './fixtures';
import { grant, OWNER_FOLDER } from './sharing';
import { recordJourneys } from './timing';

const AFTER_GRANT = 'after-the-grant.bin';

test('a grant reaches a second identity, and a revoke cuts it', async ({
  page,
  secondContext,
}, testInfo) => {
  const ownerFiles = new FilesPage(page);
  const { recipient, owner, accessibleMs } = await grant(page, secondContext, 'read');
  const recipientFiles = new FilesPage(recipient);

  await recordJourneys(testInfo, { share_to_accessible_ms: accessibleMs });

  // A file added after the grant proves the recipient reads the live folder,
  // not the listing that was current when the grant was cut.
  await owner.close();
  await ownerFiles.open(OWNER_FOLDER);
  await ownerFiles.upload(AFTER_GRANT, new Uint8Array(512).fill(9));
  await expect(ownerFiles.row(AFTER_GRANT)).toBeVisible({ timeout: 180_000 });
  await published(page);

  await expect
    .poll(
      async () => {
        await recipient.getByTestId('status-indicator').click();
        return recipientFiles.row(AFTER_GRANT).count();
      },
      { timeout: 300_000, intervals: [5_000] }
    )
    .toBe(1);

  await ownerFiles.openFromSidebar();
  await owner.open(OWNER_FOLDER);
  await owner.revoke.click();
  await expect(owner.noGrants).toBeVisible({ timeout: 60_000 });
  await owner.close();

  const list = new SharedPage(recipient);
  await list.open();
  await list.awaitStanding('revocation-signal');
  await expect(list.rows.getByTestId('shared-standing')).toHaveAttribute('data-tone', 'warning');
});
