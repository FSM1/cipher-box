import type { Page } from '@playwright/test';
import { FilesPage } from '../page-objects/files.page';
import { LoginPage } from '../page-objects/login.page';
import { redact } from './forensics';

/** A return from offline must restore the saved session before the vault can be used. */
export async function restoreVault(page: Page, timeout = 180_000): Promise<FilesPage> {
  await page.goto('/files');
  const files = new FilesPage(page);
  const login = new LoginPage(page);
  const refusal = await login.refusal(files.browser, timeout, login.walletButton);
  if (refusal !== null) {
    throw new Error(redact(`the saved session did not restore: ${refusal}`));
  }
  return files;
}
