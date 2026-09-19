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
import { SharePage } from '../page-objects/share.page';
import { SharedPage } from '../page-objects/shared.page';
import { coldStart, nodeOf } from '../vault';

const OWNER_FOLDER = 'granted-by-code';
const RECIPIENT_FOLDER = 'recipient-own';
const AFTER_GRANT = 'after-the-grant.bin';
const AFTER_GRANT_BYTES = new Uint8Array(512).fill(9);

async function savedBytes(download: Download): Promise<Uint8Array> {
  return new Uint8Array(await readFile(await download.path()));
}

test('a hand-exchanged contact code carries a grant to the second client', async ({
  page,
  browser,
}) => {
  const { files: ownerFiles, vault: owner } = await coldStart(page);
  await ownerFiles.createFolder(OWNER_FOLDER);
  const scope = nodeOf((await owner.settled()).view, OWNER_FOLDER);

  const ownerShare = new SharePage(page);
  await ownerShare.open(OWNER_FOLDER);
  const ownerCode = await ownerShare.readOwnContactCode();

  // A second context, because a second page of this one shares the origin's
  // `BroadcastChannel` and `navigator.locks` and is therefore the same session.
  const context = await browser.newContext();
  const second = await context.newPage();
  const { files: recipientFiles, vault: recipient } = await coldStart(second);
  await recipientFiles.createFolder(RECIPIENT_FOLDER);
  await recipient.settled();

  const recipientShare = new SharePage(second);
  await recipientShare.open(RECIPIENT_FOLDER);
  await recipientShare.importContact(ownerCode);
  const recipientCode = await recipientShare.readOwnContactCode();
  await recipientShare.close();

  await ownerShare.grantTo(recipientCode, 'read');
  await ownerShare.close();

  // The recipient's mailbox leg rides the nocache pass, so one refresh both
  // accepts the delivered pointer and classifies it.
  await recipient.refresh();
  const shared = new SharedPage(second);
  await shared.open();
  await shared.readStanding(scope, 'granted');
  const row = shared.row(scope);
  await expect(row).toHaveCount(1);
  await expect(row.getByTestId('shared-permission')).toHaveText('read');
  await expect(shared.error).toHaveCount(0);

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
  const recipientListing = new FilesPage(second);
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
  expect(await savedBytes(await recipientListing.save(AFTER_GRANT))).toEqual(AFTER_GRANT_BYTES);
  await expect(second.getByTestId('vault-action-error')).toHaveCount(0);

  await context.close();
});
