/**
 * A grantee with no write seed follows the scope pointer after a write cut
 * (ADR 0074). A write cut moves the scope root to a new name. The owner then
 * adds a file, and a grantee that reads only the old root does not see it.
 *
 * The downgraded writer runs in the PR gate. The personal read grantee needs a
 * third account to hold the write grant that the owner revokes, so it runs in
 * the main gate.
 */

import { expect, test } from '../fixtures';
import { SharePage } from '../page-objects/share.page';
import { SharedPage } from '../page-objects/shared.page';
import { claim, grantByCode, type CodeGrant } from '../sharing';
import { refreshedUntil } from '../vault';

const ADDED = 'added-after-the-cut.bin';

/** The owner adds a file to `folder`, and the recipient of `grant` lists it. */
async function recipientSeesAnOwnerWrite(grant: CodeGrant, folder: string): Promise<void> {
  const { ownerFiles, recipient, recipientFiles } = grant;
  await ownerFiles.open(folder);
  await ownerFiles.upload(ADDED, new Uint8Array(2_048).fill(7));
  await expect(ownerFiles.row(ADDED)).toBeVisible();
  await ownerFiles.published();

  const list = new SharedPage(grant.recipientPage);
  await list.open();
  await list.openShare(grant.scope);
  await expect(recipientFiles.breadcrumbs).toBeVisible();
  await refreshedUntil(recipient, recipientFiles.row(ADDED));
}

test('a downgraded writer sees a file the owner adds after the downgrade', async ({
  page,
  browser,
}) => {
  const folder = 'downgraded-writer';
  const grant = await grantByCode(page, browser, folder, 'write');
  await new SharedPage(grant.recipientPage).openShare(grant.scope);
  await refreshedUntil(grant.recipient, grant.recipientFiles.newFolderButton, 1, 60_000);

  const ownerShare = new SharePage(page);
  await ownerShare.open(folder);
  await ownerShare.downgradeToRead();
  await ownerShare.close();
  const list = new SharedPage(grant.recipientPage);
  await list.open();
  await list.awaitPermission('read');

  await recipientSeesAnOwnerWrite(grant, folder);
  await grant.recipientContext.close();
});

test('@full a personal read grantee sees a file the owner adds after a write revoke', async ({
  page,
  browser,
}) => {
  const folder = 'read-grantee';
  const grant = await grantByCode(page, browser, folder, 'read');
  await new SharedPage(grant.recipientPage).openShare(grant.scope);
  await expect(grant.recipientFiles.breadcrumbs).toBeVisible();

  // A third account joins through a write link, and the owner's conversion
  // commits it at write.
  const ownerShare = new SharePage(page);
  await ownerShare.open(folder);
  const link = await ownerShare.mintLink({ permission: 'write' });
  await ownerShare.close();
  const writerPage = await claim(browser, link);
  await ownerShare.openUntilGranted(folder, 2);

  // The revoke cuts the writer with the link, which is a write cut.
  await ownerShare.askToRevoke(ownerShare.writeLinkChips.first());
  await ownerShare.removeGrantees.check();
  await ownerShare.confirmLinkRevoke();
  await ownerShare.close();
  await ownerShare.openUntilGranted(folder, 1);
  await ownerShare.close();

  await recipientSeesAnOwnerWrite(grant, folder);
  await writerPage.context().close();
  await grant.recipientContext.close();
});
