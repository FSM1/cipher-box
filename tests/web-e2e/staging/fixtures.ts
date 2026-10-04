/**
 * The staging fixtures. Every page carries its own test wallet, so a spec that
 * opens a second context gets a second account without asking, and every
 * account a spec mints is removed when the spec ends.
 */

import {
  test as base,
  expect,
  type Browser,
  type Locator,
  type Page,
  type Response,
  type TestInfo,
} from '@playwright/test';
import type { Hex } from 'viem';
import { FilesPage } from '../page-objects/files.page';
import { LoginPage } from '../page-objects/login.page';
import { removeAccount, watchApiOrigin, type RemovalOutcome } from './cleanup';
import { recordForensics, redact, requestTarget, type Forensics } from './forensics';
import {
  nextStep,
  runRetryBudget,
  runRetryDeadline,
  SIGN_IN_ANNOTATION,
  SIGN_IN_RETRY_BUDGET_MS,
  type RetryStop,
  type SignInFault,
  type SignInRecord,
} from './loginRetry';
import { installTestWallet, TEST_WALLET_NAME, type TestWallet } from './wallet';

export { expect } from '@playwright/test';

/** A page in its own browser context, with the wallet it signs in under. */
export interface SecondContext {
  readonly page: Page;
  readonly wallet: TestWallet;
}

/**
 * Opens a browser context of its own. A second page of the first context would
 * share the origin's `BroadcastChannel` and `navigator.locks`, which is what
 * makes two tabs one session.
 *
 * Passing `privateKey` signs the new context in as the SAME identity subject,
 * which is a second device rather than a second account.
 */
export type OpenSecondContext = (privateKey?: Hex) => Promise<SecondContext>;

interface StagingFixtures {
  wallet: TestWallet;
  /** The API origin this tab reached, once an authentication call named one. */
  apiOrigin: () => string | null;
  secondContext: OpenSecondContext;
}

export const test = base.extend<StagingFixtures>({
  // Automatic: a page that reached the front door without one has no shipped
  // method left to sign in with.
  wallet: [
    async ({ page }, use) => {
      await use(await installTestWallet(page));
    },
    { auto: true },
  ],

  // Automatic: staging keeps whatever a run leaves behind, and nothing else
  // reclaims it. The removal is reported, never asserted — a spec fails on its
  // own subject, and `account-removal.spec.ts` is what holds the path itself
  // to a verdict. A failed spec also gets its forensics log, read before the
  // removal moves the page on.
  apiOrigin: [
    async ({ page, wallet }, use, testInfo) => {
      const origin = watchApiOrigin(page);
      const forensics = recordForensics(page);
      await use(origin);
      await attachOnFailure(testInfo, 'forensics', forensics);
      await report(testInfo, 'account-removal', await removeOnce(page, origin(), wallet.address));
    },
    { auto: true },
  ],

  secondContext: async ({ browser }: { browser: Browser }, use, testInfo) => {
    const opened: Array<{
      page: Page;
      apiOrigin: () => string | null;
      forensics: Forensics;
      address: string;
    }> = [];

    await use(async (privateKey?: Hex) => {
      const page = await (await browser.newContext()).newPage();
      const apiOrigin = watchApiOrigin(page);
      const forensics = recordForensics(page);
      const wallet = await installTestWallet(page, privateKey);
      opened.push({ page, apiOrigin, forensics, address: wallet.address });
      return { page, wallet };
    });

    for (const [index, context] of opened.entries()) {
      await attachOnFailure(testInfo, `forensics-${index + 1}`, context.forensics);
      await report(
        testInfo,
        `account-removal-${index + 1}`,
        await removeOnce(context.page, context.apiOrigin(), context.address)
      );
      await context.page.context().close();
    }
  },
});

/** The identities this worker has already taken back, as wallet addresses. */
const reclaimed = new Set<string>();

/**
 * Removes the account behind `address`, at most once per identity. Two pages
 * can hold one account — a second device signs in on the same wallet — and a
 * spec that removes explicitly still meets the automatic teardown. `DELETE
 * /account` hard-deletes the authentication rows, so a second attempt fails at
 * the refresh and reports a kept account that is in fact gone.
 */
export async function removeOnce(
  page: Page,
  apiOrigin: string | null,
  address: string
): Promise<RemovalOutcome> {
  const identity = address.toLowerCase();
  if (reclaimed.has(identity)) {
    return { removed: true, detail: 'an earlier call removed this account' };
  }
  const outcome = await removeAccount(page, apiOrigin);
  if (outcome.removed) reclaimed.add(identity);
  return outcome;
}

function report(
  testInfo: {
    attach: (name: string, options: { body: string; contentType: string }) => Promise<void>;
  },
  label: string,
  outcome: RemovalOutcome
): Promise<void> {
  return testInfo.attach(label, {
    body: `${outcome.removed ? 'removed' : 'kept'}: ${outcome.detail}`,
    contentType: 'text/plain',
  });
}

async function attachOnFailure(
  testInfo: TestInfo,
  label: string,
  forensics: Forensics
): Promise<void> {
  if (testInfo.status === testInfo.expectedStatus) return;
  await testInfo.attach(label, { body: await forensics.report(), contentType: 'text/plain' });
}

/**
 * Signs in at the front door and waits for the vault browser. Returns the
 * milliseconds the successful attempt took, which is what the timing profile
 * records.
 */
export async function signIn(page: Page): Promise<number> {
  await page.goto('/');
  return signInWithWallet(page, new FilesPage(page).browser);
}

/**
 * Signs in through the shipped wallet method on the page already open, and
 * waits for `signedIn`. Returns the milliseconds the successful attempt took.
 *
 * The auth network refuses a login under its own load, which the panel draws as
 * a banner and not as a navigation. {@link nextStep} decides whether a refusal
 * reloads the same address, fragment included, and tries again. The thrown
 * error is redacted, since it lands in a public log.
 */
export async function signInWithWallet(page: Page, signedIn: Locator): Promise<number> {
  const login = new LoginPage(page);
  const info = test.info();
  const outputDir = info.project.outputDir;
  const faults: SignInFault[] = [];
  const annotate = (result: SignInRecord['result']): void => {
    info.annotations.push({
      type: SIGN_IN_ANNOTATION,
      description: JSON.stringify({ faults, result } satisfies SignInRecord),
    });
  };

  const signInStarted = Date.now();
  const signInDeadline = signInStarted + SIGN_IN_RETRY_BUDGET_MS;
  const runDeadline = runRetryDeadline(
    outputDir,
    signInStarted,
    runRetryBudget(info.project.metadata)
  );
  for (let attempt = 0; ; attempt += 1) {
    const attemptStarted = Date.now();
    // The run window limits retries; every later login still gets its first attempt.
    const deadline = attempt === 0 ? signInDeadline : Math.min(signInDeadline, runDeadline);
    const stop: RetryStop = deadline === signInDeadline ? 'sign-in-budget' : 'run-budget';
    const stopped = `the wallet login stopped on attempt ${attempt + 1}: ${stop}`;
    const checkBudget = (): number => {
      const remaining = deadline - Date.now();
      if (remaining > 0) return remaining;
      throw new Error(stopped);
    };

    const failed: string[] = [];
    const noteRefused = (response: Response): void => {
      if (response.status() < 400) return;
      failed.push(`${requestTarget(response.url())} ${response.status()}`);
    };
    page.on('response', noteRefused);
    let started = attemptStarted;
    let refusal: string | null;
    try {
      if (attempt > 0) await page.reload({ timeout: checkBudget() });
      await expect(login.walletButton).toBeEnabled({ timeout: Math.min(60_000, checkBudget()) });
      started = Date.now();
      await login.walletButton.click({ timeout: checkBudget() });
      await page
        .getByRole('button', { name: `Connect with ${TEST_WALLET_NAME}`, exact: true })
        .click({ timeout: checkBudget() });
      refusal = await login.refusal(signedIn, Math.min(300_000, checkBudget()));
    } catch (error) {
      if (Date.now() >= deadline) {
        annotate(stop);
        throw new Error(stopped, { cause: error });
      }
      throw error;
    } finally {
      page.off('response', noteRefused);
    }
    if (refusal === null) {
      annotate(faults.length === 0 ? 'signed-in' : 'recovered');
      return Date.now() - started;
    }

    const now = Date.now();
    const step = nextStep(attempt, refusal, runDeadline - now, now - signInStarted, Math.random());
    if (step.fault !== null) faults.push({ fault: step.fault, attempt: attempt + 1 });
    if (step.action === 'fail') {
      annotate(step.result);
      throw new Error(
        redact(
          `the wallet login was refused on attempt ${attempt + 1} (${step.result}); the refusal read: ` +
            `${refusal}; the refused requests: ${failed.join(', ') || 'none'}`
        )
      );
    }
    info.setTimeout(info.timeout + (Date.now() - attemptStarted) + step.waitMs);
    await page.waitForTimeout(step.waitMs);
  }
}

/**
 * Nudges `files`' sync pass until `target` counts `count`. A focus change reads
 * what the engine already holds; only the manual refresh forces the pass that
 * reaches the record plane.
 */
export async function nudgedUntil(
  files: FilesPage,
  target: Locator,
  count = 1,
  timeout = 300_000
): Promise<void> {
  await expect
    .poll(
      async () => {
        await files.status.click();
        return target.count();
      },
      { timeout, intervals: [5_000] }
    )
    .toBe(count);
}

/** {@link FilesPage.published}, for the page a staging spec holds. */
export function published(page: Page): Promise<void> {
  return new FilesPage(page).published();
}
