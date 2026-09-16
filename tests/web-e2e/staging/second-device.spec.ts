/**
 * Profile: second device. A second browser signs in on the SAME identity and
 * reaches the same vault, and a write it makes reaches the first browser.
 *
 * Core Kit reconstructs the key on the second browser from the wallet method
 * alone, so this journey never reaches the approval rendezvous; the local
 * device-approval suite is what covers that.
 */

import { FilesPage } from '../page-objects/files.page';
import { expect, published, signIn, test } from './fixtures';

test('a second browser on the same identity reaches the same vault', async ({
  page,
  wallet,
  secondContext,
}) => {
  const first = new FilesPage(page);
  const marker = 'first-device';
  const answer = 'second-device';

  await signIn(page);
  await first.createFolder(marker);
  await expect(first.row(marker)).toBeVisible();
  await published(page);

  const { page: second } = await secondContext(wallet.privateKey);
  await signIn(second);
  const joined = new FilesPage(second);
  // The first browser's row, so this is the same vault rather than a second
  // one minted under the same wallet.
  await expect(joined.row(marker)).toBeVisible({ timeout: 300_000 });

  await joined.createFolder(answer);
  await expect(joined.row(answer)).toBeVisible();
  await published(second);

  // A focus change reads what the engine already holds; only the manual refresh
  // forces the pass that reaches the record plane.
  await expect
    .poll(
      async () => {
        await first.status.click();
        return first.row(answer).count();
      },
      { timeout: 300_000, intervals: [5_000] }
    )
    .toBe(1);
});
