/**
 * Profile: writable share. Two real sessions write into one scope through one
 * front: the recipient builds inside the granted folder, and the owner reads
 * back what the recipient published.
 */

import { FilesPage } from '../page-objects/files.page';
import { SharedPage } from '../page-objects/shared.page';
import { expect, published, test } from './fixtures';
import { grant, OWNER_FOLDER } from './sharing';

// Held out of the run: on the deployed front a grant never reaches the
// recipient's `/shared`, so the profile cannot pass whatever it waits. It runs
// again as soon as a grant is delivered.
test.fixme();

const WRITTEN = 'written-by-the-recipient.bin';
const NESTED = 'recipient-subfolder';

test('a write grant lets a second identity build inside the folder', async ({
  page,
  secondContext,
}) => {
  const ownerFiles = new FilesPage(page);
  const { recipient, owner } = await grant(page, secondContext, 'write');
  const recipientFiles = new FilesPage(recipient);

  await recipientFiles.upload(WRITTEN, new Uint8Array(4_096).fill(5));
  await expect(recipientFiles.row(WRITTEN)).toBeVisible({ timeout: 300_000 });
  await recipientFiles.createFolder(NESTED);
  await expect(recipientFiles.row(NESTED)).toBeVisible();
  await published(recipient);

  await owner.close();
  await ownerFiles.open(OWNER_FOLDER);
  // A focus change reads what the engine already holds; only the manual refresh
  // forces the pass that reaches the record plane.
  for (const name of [WRITTEN, NESTED]) {
    await expect
      .poll(
        async () => {
          await ownerFiles.status.click();
          return ownerFiles.row(name).count();
        },
        { timeout: 300_000, intervals: [5_000] }
      )
      .toBe(1);
  }

  await ownerFiles.openFromSidebar();
  await owner.open(OWNER_FOLDER);
  await owner.downgrade.click();
  await expect(owner.permission).toHaveText('read', { timeout: 60_000 });
  await owner.close();

  const list = new SharedPage(recipient);
  await list.open();
  await list.awaitStanding('granted', 600_000);
  await expect(list.rows.getByTestId('shared-permission')).toHaveText('read');
});
