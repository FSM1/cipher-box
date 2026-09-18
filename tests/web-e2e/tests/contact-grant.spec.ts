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

import { expect, test } from '../fixtures';
import { SharePage } from '../page-objects/share.page';
import { SharedPage } from '../page-objects/shared.page';
import { coldStart, nodeOf } from '../vault';

const OWNER_FOLDER = 'granted-by-code';
const RECIPIENT_FOLDER = 'recipient-own';

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
  await shared.readAgain();
  const row = shared.row(scope);
  await expect(row).toHaveCount(1);
  await expect(row.getByTestId('shared-standing')).toHaveAttribute('data-resolution', 'granted');
  await expect(shared.error).toHaveCount(0);

  await context.close();
});
