/**
 * Profile: first login and vault mint. The real login round trip, the root
 * record published through the routing front, and the session across a reload
 * and a second sign-in.
 */

import { FilesPage } from '../page-objects/files.page';
import { LoginPage } from '../page-objects/login.page';
import { expect, published, signIn, test } from './fixtures';

test('a fresh identity mints a vault, and the session survives a reload', async ({ page }) => {
  const files = new FilesPage(page);
  // A row no other run holds. An empty-state check alone passes when a
  // reauthentication mints a second empty vault; this row does not survive that.
  const marker = `mint-${Date.now().toString(36)}`;

  await signIn(page);
  await expect(files.emptyState).toBeVisible();

  await files.createFolder(marker);
  await expect(files.row(marker)).toBeVisible();
  await published(page);

  await page.reload();
  await expect(files.browser).toBeVisible({ timeout: 180_000 });
  await expect(files.row(marker)).toBeVisible({ timeout: 180_000 });

  await files.signOut();
  await expect(new LoginPage(page).walletButton).toBeVisible();

  // The same wallet, so the second sign-in reaches the account the first minted
  // rather than a new one; this device already holds its factor.
  await signIn(page);
  await expect(files.row(marker)).toBeVisible({ timeout: 180_000 });
});
