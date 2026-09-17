/**
 * Profile: the removal every other profile relies on. Staging keeps whatever a
 * run leaves behind, so the run has to take it back — and a removal that is
 * only ever reported drifts silently. This is the one spec that fails when the
 * path stops working.
 */

import { FilesPage } from '../page-objects/files.page';
import { expect, published, removeOnce, signIn, test } from './fixtures';

test('a run removes the account it mints', async ({ page, apiOrigin, wallet }) => {
  const files = new FilesPage(page);
  await signIn(page);

  // Something to reclaim: an account that published nothing exercises none of
  // the inventory retirement the removal does.
  await files.upload('removal.bin', new Uint8Array(1_024).fill(3));
  await expect(files.row('removal.bin')).toBeVisible({ timeout: 180_000 });
  await published(page);

  const outcome = await removeOnce(page, apiOrigin(), wallet.address);
  expect(outcome.removed, outcome.detail).toBe(true);
});
