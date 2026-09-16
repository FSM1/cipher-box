/**
 * The two halves of a staging share: an owner with a folder to grant, and a
 * second identity that reads it back. Both sides are driven through the chrome,
 * because a deployed bundle carries no introspection hook.
 */

import type { Page } from '@playwright/test';
import { FilesPage } from '../page-objects/files.page';
import { SharePage } from '../page-objects/share.page';
import { SharedPage } from '../page-objects/shared.page';
import { expect, published, signIn, type OpenSecondContext } from './fixtures';

/** The folder each side owns; the recipient needs one to reach its own code. */
export const OWNER_FOLDER = 'granted';
export const RECIPIENT_FOLDER = 'recipient-own';

export interface Share {
  readonly recipient: Page;
  readonly owner: SharePage;
  /** Milliseconds from the grant to the recipient reading the folder. */
  readonly accessibleMs: number;
}

/**
 * Grants `OWNER_FOLDER` from `page` to a second identity and opens it there.
 * Leaves the owner's share dialog open, which is where a revoke or a downgrade
 * goes next.
 */
export async function grant(
  page: Page,
  openSecond: OpenSecondContext,
  permission: 'read' | 'write'
): Promise<Share> {
  const ownerFiles = new FilesPage(page);
  await signIn(page);
  await ownerFiles.createFolder(OWNER_FOLDER);
  await expect(ownerFiles.row(OWNER_FOLDER)).toBeVisible();
  await published(page);

  const { page: recipient } = await openSecond();
  const recipientFiles = new FilesPage(recipient);
  await signIn(recipient);
  await recipientFiles.createFolder(RECIPIENT_FOLDER);
  await expect(recipientFiles.row(RECIPIENT_FOLDER)).toBeVisible();
  await published(recipient);

  const recipientShare = new SharePage(recipient);
  await recipientShare.open(RECIPIENT_FOLDER);
  const code = await recipientShare.readOwnContactCode();
  await recipientShare.close();

  const owner = new SharePage(page);
  await owner.open(OWNER_FOLDER);
  const started = Date.now();
  await owner.grantTo(code, permission);

  const list = new SharedPage(recipient);
  await list.open();
  await list.awaitStanding('granted', 600_000);
  await list.rows.getByTestId('shared-open').click();
  await expect(new FilesPage(recipient).breadcrumbs).toBeVisible({ timeout: 180_000 });

  return { recipient, owner, accessibleMs: Date.now() - started };
}
