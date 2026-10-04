import { expect, type Page } from '@playwright/test';
import { FilesPage } from '../page-objects/files.page';
import { LoginPage } from '../page-objects/login.page';
import { redact } from './forensics';

/** A return from offline must restore the saved session before the vault can be used. */
export async function restoreVault(page: Page, timeout = 180_000): Promise<FilesPage> {
  await page.goto('/files');
  const files = new FilesPage(page);
  const login = new LoginPage(page);
  let refusal: string | null = null;
  await expect
    .poll(
      async () => {
        if (await files.browser.isVisible()) return true;
        const banner = login.error.first();
        if (await banner.isVisible()) {
          refusal = (await banner.innerText()).trim() || 'an empty refusal banner';
          return true;
        }
        if (await login.walletButton.isVisible()) {
          refusal = 'returned to sign-in without an error';
          return true;
        }
        return false;
      },
      { timeout, intervals: [250], message: 'the saved session did not restore the file browser' }
    )
    .toBe(true);
  if (refusal !== null) {
    throw new Error(redact(`the saved session did not restore: ${refusal}`));
  }
  return files;
}
