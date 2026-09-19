/**
 * The PR gate's write grant: the recipient of a folder granted for writing
 * builds inside it, and the owner reads back what the recipient published.
 *
 * A grantee's delete only unlinks the node. The owner's engine bins it by owner
 * capture, so the deleted file lands in the owner's bin and never in the
 * recipient's.
 */

import { expect, test } from '../fixtures';
import { BinPage } from '../page-objects/bin.page';
import type { FilesPage } from '../page-objects/files.page';
import { SharedPage } from '../page-objects/shared.page';
import type { VaultPage } from '../page-objects/vault.page';
import { grantByCode } from '../sharing';

const OWNER_FOLDER = 'granted-for-writing';
const WRITTEN = 'written-by-the-recipient.bin';
const NESTED = 'recipient-subfolder';

/** Refreshes `vault` until `files` lists `name` exactly `count` times. */
async function listsUntil(
  vault: VaultPage,
  files: FilesPage,
  name: string,
  count: number
): Promise<void> {
  await expect
    .poll(
      async () => {
        await vault.refresh();
        return files.row(name).count();
      },
      { timeout: 120_000, intervals: [2_000] }
    )
    .toBe(count);
}

test('a write grant lets the second client build inside the folder', async ({ page, browser }) => {
  const grant = await grantByCode(page, browser, OWNER_FOLDER, 'write');
  const { owner, ownerFiles, recipient, recipientFiles } = grant;

  await new SharedPage(grant.recipientPage).openShare(grant.scope);
  await expect(recipientFiles.breadcrumbs).toBeVisible();
  // The browser offers the write once the engine's pass has proved the grant.
  await expect
    .poll(
      async () => {
        await recipient.refresh();
        return recipientFiles.newFolderButton.count();
      },
      { timeout: 60_000, intervals: [2_000] }
    )
    .toBe(1);

  await recipientFiles.upload(WRITTEN, new Uint8Array(4_096).fill(5));
  await expect(recipientFiles.row(WRITTEN)).toBeVisible();
  await recipientFiles.createFolder(NESTED);
  await expect(recipientFiles.row(NESTED)).toBeVisible();
  await recipientFiles.published();
  await expect(recipientFiles.row(WRITTEN)).toBeVisible();

  await ownerFiles.open(OWNER_FOLDER);
  for (const name of [WRITTEN, NESTED]) {
    await listsUntil(owner, ownerFiles, name, 1);
  }

  await recipientFiles.remove(WRITTEN);
  await expect(recipientFiles.row(WRITTEN)).toHaveCount(0);
  await recipientFiles.published();
  await listsUntil(owner, ownerFiles, WRITTEN, 0);

  const ownerBin = new BinPage(page);
  await ownerBin.open();
  await ownerBin.appeared(WRITTEN);
  const recipientBin = new BinPage(grant.recipientPage);
  await recipientBin.open();
  await expect(recipientBin.empty).toBeVisible();

  await grant.recipientContext.close();
});
