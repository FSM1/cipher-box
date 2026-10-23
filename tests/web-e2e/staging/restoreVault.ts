import type { Locator, Page } from '@playwright/test';
import { FilesPage } from '../page-objects/files.page';
import { LoginPage, refusalText, type SignInOutcome } from '../page-objects/login.page';
import { signInWithWallet } from './fixtures';
import { redact, watchRefusedRequests } from './forensics';
import { devnetFault } from './loginRetry';

/** The refused resume, in full and redacted, so the public log names its cause. */
function notRestored(refusal: string, refused: readonly string[] = []): Error {
  return new Error(
    redact(
      `the saved session did not restore: ${refusal}; ` +
        `devnet fault: ${devnetFault(refusal, refused) ?? 'none'}; ` +
        `the refused requests: ${refused.join(', ') || 'none'}`
    )
  );
}

/** Waits for the resume on `page` to settle. */
function resumed(page: Page, signedIn: Locator, timeout: number): Promise<SignInOutcome> {
  const login = new LoginPage(page);
  return login.outcome(signedIn, timeout, login.walletButton);
}

/**
 * Waits for the session resume on `page` to reach `signedIn`. A devnet fault
 * of the resume is the first refused attempt of {@link signInWithWallet}; any
 * other refusal throws, since a new login would hide a lost session.
 */
export async function resumeSession(
  page: Page,
  signedIn: Locator,
  timeout = 180_000
): Promise<void> {
  const watch = watchRefusedRequests(page);
  const outcome = await resumed(page, signedIn, timeout).finally(watch.stop);
  if (outcome.kind === 'signed-in') return;
  const refusal = refusalText(outcome);
  if (devnetFault(refusal, watch.requests) === null) throw notRestored(refusal, watch.requests);
  await signInWithWallet(page, signedIn, refusal, watch.requests);
}

/** A return from offline must restore the saved session before the vault can be used. */
export async function restoreVault(page: Page, timeout = 180_000): Promise<FilesPage> {
  await page.goto('/files');
  const files = new FilesPage(page);
  await resumeSession(page, files.browser, timeout);
  return files;
}

/** A reload must keep the session: any refused resume throws, with no new login. */
export async function reloadVault(page: Page): Promise<FilesPage> {
  await page.reload();
  const files = new FilesPage(page);
  const outcome = await resumed(page, files.browser, 180_000);
  if (outcome.kind !== 'signed-in') throw notRestored(refusalText(outcome));
  return files;
}
