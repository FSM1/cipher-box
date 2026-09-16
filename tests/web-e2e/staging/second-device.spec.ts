/**
 * Profile: second device. A second browser signs in on the SAME identity, which
 * holds no factor there, and joins the vault over the real approval rendezvous
 * (ADR 0009) rather than over a hook.
 */

import { FilesPage } from '../page-objects/files.page';
import { SettingsPage } from '../page-objects/settings.page';
import { connectWallet, expect, published, signIn, test } from './fixtures';

test('a second browser joins the same identity after an approval', async ({
  page,
  wallet,
  secondContext,
}) => {
  const files = new FilesPage(page);
  const marker = `device-${Date.now().toString(36)}`;

  await signIn(page);
  await files.createFolder(marker);
  await expect(files.row(marker)).toBeVisible();
  await published(page);

  // Only a registered device is offered a request to answer.
  const settings = new SettingsPage(page);
  await settings.open();
  await expect(settings.devices).toBeVisible();
  await settings.registerDevice();

  const { page: second } = await secondContext(wallet.privateKey);
  await connectWallet(second);
  const approve = second.getByTestId('recovery-choose-approve');
  await expect(approve).toBeVisible({ timeout: 180_000 });
  await approve.click();

  const asked = second.getByTestId('approval-comparison-value');
  await expect(asked).not.toBeEmpty({ timeout: 120_000 });
  const comparison = ((await asked.textContent()) ?? '').trim();

  const prompt = page.getByTestId('approval-prompt');
  await expect(prompt).toBeVisible({ timeout: 300_000 });
  // The two devices must show the same value; approving on a different one is
  // the attack the comparison exists to stop.
  await expect(prompt.getByTestId('approval-comparison-value')).toHaveText(comparison);
  await page.getByTestId('approval-match').check();
  await page.getByTestId('approval-approve').click();

  await second.waitForURL('**/files', { timeout: 300_000 });
  const joined = new FilesPage(second);
  await expect(joined.browser).toBeVisible({ timeout: 180_000 });
  await expect(joined.row(marker)).toBeVisible({ timeout: 180_000 });
});
