/**
 * The PR gate's contact-code grant: two accounts that exchange codes by hand,
 * with no invite link anywhere.
 *
 * The link flow hands the claimant the owner's contact bundle as part of the
 * claim, so it can never show what a hand exchange leaves out. A contact code
 * is the only other way an identity key arrives (blueprint/engine.md "Contact
 * import"), and the recipient drops a mailbox item whose sender its own book
 * does not anchor — so this drives both directions and reads the row back.
 */

import { readFile } from 'node:fs/promises';
import type { Download } from '@playwright/test';
import { expect, test } from '../fixtures';
import { FilesPage } from '../page-objects/files.page';
import { SharedPage } from '../page-objects/shared.page';
import { grantByCode } from '../sharing';

const OWNER_FOLDER = 'granted-by-code';
const AFTER_GRANT = 'after-the-grant.bin';
const AFTER_GRANT_BYTES = new Uint8Array(512).fill(9);

async function savedBytes(download: Download): Promise<Uint8Array> {
  return new Uint8Array(await readFile(await download.path()));
}

test('a hand-exchanged contact code carries a grant to the second client', async ({
  page,
  browser,
}) => {
  const { ownerFiles, recipient, recipientPage, recipientContext, scope } = await grantByCode(
    page,
    browser,
    OWNER_FOLDER,
    'read'
  );
  const shared = new SharedPage(recipientPage);

  // A file the owner adds after the grant publishes into the scope root the
  // grant cut, and the recipient reads the live folder rather than the listing
  // that was current at the grant.
  await ownerFiles.open(OWNER_FOLDER);
  await ownerFiles.upload(AFTER_GRANT, AFTER_GRANT_BYTES);
  const added = ownerFiles.row(AFTER_GRANT);
  await expect(added).toBeVisible();
  await ownerFiles.published();
  await expect(added).toBeVisible();
  // The grant re-sealed the folder into its own scope, so the owner's read opens
  // under that scope rather than the vault root.
  expect(await savedBytes(await ownerFiles.save(AFTER_GRANT))).toEqual(AFTER_GRANT_BYTES);
  await expect(page.getByTestId('vault-action-error')).toHaveCount(0);

  await shared.openShare(scope);
  const recipientListing = new FilesPage(recipientPage);
  await expect(recipientListing.breadcrumbs).toBeVisible();
  await expect
    .poll(
      async () => {
        await recipient.refresh();
        return recipientListing.row(AFTER_GRANT).count();
      },
      { timeout: 60_000, intervals: [2_000] }
    )
    .toBe(1);
  await expect(recipientListing.readOnlyNotice).toBeVisible();
  await expect(recipientListing.newFolderButton).toHaveCount(0);
  expect(await savedBytes(await recipientListing.save(AFTER_GRANT))).toEqual(AFTER_GRANT_BYTES);
  await expect(recipientPage.getByTestId('vault-action-error')).toHaveCount(0);

  await recipientContext.close();
});
