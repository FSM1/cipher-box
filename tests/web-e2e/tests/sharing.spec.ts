/**
 * The owner's half of sharing: the grant list a folder carries, the contact
 * import that names a recipient, and the invite link's mint-and-revoke life.
 *
 * Every assertion here reads the engine back through the dialog, which re-reads
 * after each command — so nothing passes on an optimistic render.
 */

import { expect, test } from '../fixtures';
import { SharePage } from '../page-objects/share.page';
import { coldStart } from '../vault';

const FOLDER = 'shared-folder';

test('a folder offers sharing, and grants nothing before a recipient exists', async ({ page }) => {
  const { files, vault } = await coldStart(page);
  await files.createFolder(FOLDER);
  await vault.settled();
  const share = new SharePage(page);

  await share.open(FOLDER);

  await expect(share.noGrants).toBeVisible();
  await expect(share.standingUnknown).toHaveCount(0);
  // No contact is imported, so the one recipient a fresh vault can name is the
  // bearer of a link.
  await expect(share.noContacts).toBeVisible();
  await expect(share.grantButton).toBeDisabled();
  await expect(share.mintButton).toBeEnabled();
});

test('@full a minted invite link names the claim route and is held until it is dismissed', async ({
  page,
}) => {
  const { files, vault } = await coldStart(page);
  await files.createFolder(FOLDER);
  await vault.settled();
  const share = new SharePage(page);
  await share.open(FOLDER);

  const link = await share.mintLink('30 days');

  expect(link.origin).toBe(new URL(page.url()).origin);
  expect(link.pathname).toBe('/invite');
  // The whole capability rides the fragment, so nothing of it reaches a server
  // log or a Referer header.
  expect(link.search).toBe('');
  expect(link.hash.length).toBeGreaterThan(1);
  await expect(share.bearerNote).toBeVisible();
  // Shown once: the incidental dismissals are refused so only the deliberate
  // exit discards the one copy of a live capability.
  await expect(share.dismiss).toBeDisabled();

  await share.close();
  await share.open(FOLDER);

  // The scope now carries a link, so the mint gives way to the link's standing.
  await expect(share.liveLink).toBeVisible();
  await expect(share.liveLinkExpiry).toContainText('expires');
  await expect(share.mintButton).toHaveCount(0);
  // A second visit does not re-show the capability.
  await expect(share.mintedLink).toHaveCount(0);
});

test('@full revoking the link leaves the scope it cut, and the engine names why no second one mints', async ({
  page,
}) => {
  const { files, vault } = await coldStart(page);
  await files.createFolder(FOLDER);
  await vault.settled();
  const share = new SharePage(page);
  await share.open(FOLDER);
  await share.mintLink();
  await share.close();
  await share.open(FOLDER);
  await expect(share.liveLink).toBeVisible();

  await share.revokeLinkButton.click();

  await expect(share.liveLink).toHaveCount(0);
  await expect(share.error).toHaveCount(0);
  // The mint cut a scope, and a scope outlives the link that cut it — so the
  // folder now refuses both a second link and a grant of its own, each under
  // the engine's own check name.
  await expect(share.noMint).toHaveAttribute('data-check', 'invite-target-already-names-a-scope');
  await expect(share.noGrant).toHaveAttribute('data-check', 'grant-target-already-names-a-scope');
  await expect(share.mintButton).toHaveCount(0);
  await expect(share.grantButton).toBeDisabled();
});

test('@full the contact import refuses what it cannot read, and leaving retires the refusal', async ({
  page,
}) => {
  const { files, vault } = await coldStart(page);
  await files.createFolder(FOLDER);
  await vault.settled();
  const share = new SharePage(page);
  await share.open(FOLDER);

  await share.openImport();

  // An exchange needs both codes, so the step hands this member's own code over
  // beside the paste field.
  await expect(share.ownContactCode).toBeVisible();

  // Not hex at all: the form itself will not submit it.
  await share.contactCode.fill('not a contact code');
  await expect(share.importUnreadable).toBeVisible();
  await expect(share.importConfirm).toBeDisabled();

  // Readable as bytes, but no contact code — so the refusal is the engine's,
  // and the form stands so the paste can be corrected.
  await share.contactCode.fill('00ff10');
  await share.importConfirm.click();
  await expect(share.error).toBeVisible();
  await expect(share.importForm).toBeVisible();

  await share.cancelImport();

  await expect(share.error).toHaveCount(0);
  await expect(share.noContacts).toBeVisible();
});
