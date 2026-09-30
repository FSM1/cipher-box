/**
 * The soak fixtures. They sign in as the two durable soak accounts from the
 * `SOAK_*` wallet keys and extend the bare Playwright `test`, not the staging
 * one, so no teardown removes an account (ADR 0053 D4).
 */

import { test as base, type BrowserContext, type Page } from '@playwright/test';
import { signIn } from '../fixtures';
import { installTestWallet } from '../wallet';
import { soakWalletKey, type SoakRole } from './accounts';
import { SoakFailure, type FailureReason } from './reasons';
import { record, shortDetail, unrecordedFailure } from './summary';

export { expect } from '@playwright/test';

/** Opens a fresh browser context, signed in as the soak grantee. */
export type OpenGrantee = () => Promise<Page>;

interface SoakFixtures {
  /** The default page, signed in as the soak owner. */
  owner: Page;
  grantee: OpenGrantee;
  failClosed: void;
}

/** The failures that {@link check} recorded in this worker. */
let recordedFailures = 0;

export const test = base.extend<SoakFixtures>({
  // Automatic, and torn down last: a failure outside every check still reaches
  // the summary, and a test that never reaches this teardown leaves no `ended`
  // line.
  failClosed: [
    // eslint-disable-next-line no-empty-pattern -- Playwright reads the fixture list from this pattern.
    async ({}, use, testInfo) => {
      const before = recordedFailures;
      await record({ kind: 'test', test: testInfo.title, phase: 'started' });
      await use();
      const missed = unrecordedFailure(testInfo, recordedFailures - before);
      if (missed !== null) await record(missed);
      await record({ kind: 'test', test: testInfo.title, phase: 'ended' });
    },
    { auto: true },
  ],

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
 * Runs one soak check, records its outcome, and returns what the body returned.
 * A failure carries `reason` unless the body threw a {@link SoakFailure} that
 * names its own.
 */
export async function check<T>(
  name: string,
  reason: FailureReason,
  body: () => Promise<T>
): Promise<T> {
  let value: T;
  try {
    value = await body();
  } catch (error) {
    const failure =
      error instanceof SoakFailure
        ? error
        : new SoakFailure(reason, error instanceof Error ? error.message : String(error), {
            cause: error,
          });
    recordedFailures += 1;
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
  return value;
}

export function fact(label: string, value: string): Promise<void> {
  return record({ kind: 'fact', label, value: shortDetail(value) });
}
