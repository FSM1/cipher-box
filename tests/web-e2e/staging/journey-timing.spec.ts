/**
 * Profile: journey timing. The login and upload legs; the sharing profile
 * records the share leg, because that is where a second identity already is.
 */

import { FilesPage } from '../page-objects/files.page';
import { expect, signIn, test } from './fixtures';
import { recordJourneys } from './timing';

test('the journeys stay within the committed baseline', async ({ page }, testInfo) => {
  const files = new FilesPage(page);

  const loginToVault = await signIn(page);

  const started = Date.now();
  await files.upload('timing.bin', new Uint8Array(16 * 1024).fill(7));
  await expect(files.row('timing.bin')).toBeVisible({ timeout: 180_000 });
  const uploadToVisible = Date.now() - started;

  await recordJourneys(testInfo, {
    login_to_vault_ms: loginToVault,
    upload_to_visible_ms: uploadToVisible,
  });
});
