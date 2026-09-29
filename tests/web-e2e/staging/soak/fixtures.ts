/**
 * The soak fixtures. They sign in as the two durable soak accounts from the
 * `SOAK_*` wallet keys and extend the bare Playwright `test`, not the staging
 * one, so no teardown removes an account (ADR 0053 D4).
 */

import { test as base, type BrowserContext, type Page } from '@playwright/test';
import { signIn } from '../fixtures';
import { installTestWallet } from '../wallet';
import { soakWalletKey, type SoakRole } from './accounts';
import { SoakFailure, type FailureReason, type SkipReason } from './reasons';
import { record, shortDetail } from './summary';

export { expect } from '@playwright/test';

/** Opens a fresh browser context, signed in as the soak grantee. */
export type OpenGrantee = () => Promise<Page>;

interface SoakFixtures {
  /** The default page, signed in as the soak owner. */
  owner: Page;
  grantee: OpenGrantee;
}

export const test = base.extend<SoakFixtures>({
  owner: async ({ page }, use) => {
    await signInAs(page, 'owner');
    await use(page);
  },

  grantee: async ({ browser }, use) => {
    const opened: BrowserContext[] = [];
    await use(async () => {
      const context = await browser.newContext();
      opened.push(context);
      const page = await context.newPage();
      await signInAs(page, 'grantee');
      return page;
    });
    for (const context of opened) await context.close();
  },
});

async function signInAs(page: Page, role: SoakRole): Promise<void> {
  await check(`${role} sign-in`, 'sign-in-failed', async () => {
    await installTestWallet(page, soakWalletKey(process.env, role));
    await signIn(page);
  });
}

/**
 * Runs one soak check and records its outcome. A failure carries `reason`
 * unless the body threw a {@link SoakFailure} that names its own.
 */
export async function check(
  name: string,
  reason: FailureReason,
  body: () => Promise<void>
): Promise<void> {
  try {
    await body();
  } catch (error) {
    const failure =
      error instanceof SoakFailure
        ? error
        : new SoakFailure(reason, error instanceof Error ? error.message : String(error), {
            cause: error,
          });
    await record({
      kind: 'check',
      check: name,
      outcome: 'failed',
      reason: failure.reason,
      detail: shortDetail(failure.detail),
    });
    throw failure;
  }
  await record({ kind: 'check', check: name, outcome: 'passed' });
}

/** Records a skipped check and skips the test that holds it. */
export async function skipCheck(name: string, reason: SkipReason, detail: string): Promise<void> {
  await record({
    kind: 'check',
    check: name,
    outcome: 'skipped',
    reason,
    detail: shortDetail(detail),
  });
  test.skip(true, `[${reason}] ${detail}`);
}

export function fact(label: string, value: string): Promise<void> {
  return record({ kind: 'fact', label, value: shortDetail(value) });
}
