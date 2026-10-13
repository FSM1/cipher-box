import type { Locator, Page } from '@playwright/test';
import { FilesPage } from '../page-objects/files.page';
import { LoginPage } from '../page-objects/login.page';
import { signInWithWallet } from './fixtures';
import { redact } from './forensics';
import { devnetFault } from './loginRetry';

/** The refused resume, in full and redacted, so the public log names its cause. */
function notRestored(refusal: string): Error {
  return new Error(
    redact(
      `the saved session did not restore: ${refusal}; devnet fault: ${devnetFault(refusal) ?? 'none'}`
    )
  );
}

/**
 * Waits for the session resume on `page` to reach `signedIn`. A devnet fault
 * of the resume signs in again through {@link signInWithWallet}; any other
 * refusal throws, since a new login would hide a lost session.
 */
export async function resumeSession(
  page: Page,
  signedIn: Locator,
  timeout = 180_000
): Promise<void> {
  const login = new LoginPage(page);
  const refusal = await login.refusal(signedIn, timeout, login.walletButton);
  if (refusal === null) return;
  if (devnetFault(refusal) === null) throw notRestored(refusal);
  await signInWithWallet(page, signedIn);
}

/** A return from offline must restore the saved session before the vault can be used. */
export async function restoreVault(page: Page, timeout = 180_000): Promise<FilesPage> {
  await page.goto('/files');
  const files = new FilesPage(page);
  await resumeSession(page, files.browser, timeout);
  return files;
}

/** A reload must keep the session: any refused resume throws, with no new login. */
export async function reloadVault(page: Page, timeout = 180_000): Promise<FilesPage> {
  await page.reload();
  const files = new FilesPage(page);
  const login = new LoginPage(page);
  const refusal = await login.refusal(files.browser, timeout, login.walletButton);
  if (refusal !== null) throw notRestored(refusal);
  return files;
}
