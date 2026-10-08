import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  DEADLINE_FILE,
  devnetFault,
  nextStep,
  RUN_RETRY_BUDGET_KEY,
  SIGN_IN_RETRY_BUDGET_MS,
  runRetryBudget,
  runRetryDeadline,
  RUN_SIGN_IN_RETRY_BUDGET_MS,
  summarize,
} from './loginRetry';

const NONCE = 'could not retrieve nonce: Internal error';
const FULL_RUN_WINDOW = RUN_SIGN_IN_RETRY_BUDGET_MS;

describe('devnetFault', () => {
  it.each([
    [
      'could not retrieve nonce: Internal error, failed to get nonce with status code: 503',
      'nonce',
    ],
    ['Cannot perform rss round 1', 'rss-round'],
    ['master poly commits inconsistent with tssPubKey', 'poly-commits'],
    ['Unable to resolve enough promises', 'node-quorum'],
    ['the request to node-1.dev-node.web3auth.io failed with status 500', 'node-5xx'],
    [
      'undefined unable to assign key, All auth network nodes are currently busy, Please try again.',
      'node-busy',
    ],
    ['unable to assign key; all auth network nodes are currently busy - try again', 'node-busy'],
    [
      'undefined Unable to assign key, failed to fetch key assign result please try again',
      'key-assign',
    ],
  ])('classes %s', (refusal, fault) => {
    expect(devnetFault(refusal)).toBe(fault);
  });

  it.each([
    'the wallet signature was rejected',
    'the request to api.example.com failed with status 500',
    'the request to node-1.dev-node.web3auth.io failed with status 401',
  ])('fails at once on %s', (refusal) => {
    expect(devnetFault(refusal)).toBeNull();
  });
});

describe('summarize', () => {
  it('distinguishes terminal faults and the two time limits', () => {
    expect(
      summarize([
        { faults: [], result: 'signed-in' },
        { faults: [{ fault: 'nonce', attempt: 1 }], result: 'recovered' },
        {
          faults: [
            { fault: 'nonce', attempt: 1 },
            { fault: 'rss-round', attempt: 2 },
          ],
          result: 'sign-in-budget',
        },
        { faults: [], result: 'refused' },
        { faults: [{ fault: 'node-5xx', attempt: 1 }], result: 'run-budget' },
        { faults: [{ fault: 'node-busy', attempt: 2 }], result: 'sign-in-budget' },
      ])
    ).toBe(
      'sign-ins: 6, recovered: 1, observed faults: nonce=2 rss-round=1 node-5xx=1 node-busy=1, ' +
        'sign-in budget exhausted: 2, ' +
        'retries suppressed by run budget: 1, refused: 1'
    );
  });

  it('reads an empty run', () => {
    expect(summarize([])).toBe(
      'sign-ins: 0, recovered: 0, observed faults: none, ' +
        'sign-in budget exhausted: 0, retries suppressed by run budget: 0, refused: 0'
    );
  });
});

describe('nextStep', () => {
  it('fails at once on a refusal that is not a devnet fault', () => {
    expect(nextStep(0, 'the wallet signature was rejected', FULL_RUN_WINDOW, 0, 1)).toEqual({
      action: 'fail',
      fault: null,
      result: 'refused',
    });
  });

  it.each([
    [0, 0, 15_000],
    [0, 1, 20_000],
    [1, 0, 25_000],
    [1, 1, 30_000],
    [13, 0.5, 27_500],
    [100, 1, 30_000],
  ])('bounds the delay on attempt %s with jitter %s', (attempt, jitter, waitMs) => {
    expect(nextStep(attempt, NONCE, FULL_RUN_WINDOW, 0, jitter)).toEqual({
      action: 'retry',
      fault: 'nonce',
      waitMs,
    });
  });

  it('reports run-budget suppression', () => {
    expect(nextStep(0, NONCE, 0, 0, 1)).toEqual({
      action: 'fail',
      fault: 'nonce',
      result: 'run-budget',
    });
  });
});

describe('nextStep budget', () => {
  it('retries while the wait still fits in the budget of one sign-in', () => {
    const waitMs = 30_000;
    expect(nextStep(1, NONCE, FULL_RUN_WINDOW, SIGN_IN_RETRY_BUDGET_MS - waitMs - 1, 1)).toEqual({
      action: 'retry',
      fault: 'nonce',
      waitMs,
    });
  });

  it('stops at the sign-in limit when a wait leaves no time for the next attempt', () => {
    const waitMs = 30_000;
    expect(nextStep(1, NONCE, FULL_RUN_WINDOW, SIGN_IN_RETRY_BUDGET_MS - waitMs, 1)).toEqual({
      action: 'fail',
      fault: 'nonce',
      result: 'sign-in-budget',
    });
  });

  it('does not start a wait that consumes the remaining run window', () => {
    const waitMs = 20_000;
    expect(nextStep(0, NONCE, waitMs, 0, 1)).toMatchObject({
      action: 'fail',
      result: 'run-budget',
    });
    expect(nextStep(0, NONCE, waitMs + 1, 0, 1)).toMatchObject({ action: 'retry', waitMs });
  });
});

describe('the retry window across logins and workers', () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'login-retry-'));
  });
  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('allows a later login to retry after an earlier login exhausts its time budget', () => {
    const outputDir = join(root, 'test-results');
    const now = 1_000_000;
    const deadline = runRetryDeadline(outputDir, now);
    expect(deadline).toBe(now + RUN_SIGN_IN_RETRY_BUDGET_MS);
    expect(nextStep(4, NONCE, deadline - now, SIGN_IN_RETRY_BUDGET_MS, 1)).toMatchObject({
      action: 'fail',
      result: 'sign-in-budget',
    });
    // A replacement worker reads the same file, with no state from the failed login.
    const later = now + SIGN_IN_RETRY_BUDGET_MS;
    const laterDeadline = runRetryDeadline(outputDir, later);
    expect(laterDeadline).toBe(deadline);
    expect(nextStep(0, NONCE, laterDeadline - later, 0, 1)).toMatchObject({ action: 'retry' });
    expect(nextStep(0, NONCE, laterDeadline - (deadline + 1), 0, 1)).toMatchObject({
      action: 'fail',
      result: 'run-budget',
    });
  });

  it('starts the window with the budget a project passes', () => {
    expect(runRetryDeadline(root, 1_000_000, 13_200_000)).toBe(14_200_000);
    expect(runRetryDeadline(root, 2_000_000, 60_000)).toBe(14_200_000);
  });

  it('refuses corrupt persisted state instead of silently granting a new window', () => {
    runRetryDeadline(root, 1_000_000);
    writeFileSync(join(root, DEADLINE_FILE), 'not a deadline');
    expect(() => runRetryDeadline(root, 2_000_000)).toThrow('retry deadline is invalid');
  });
});

describe('runRetryBudget', () => {
  it('uses the default when the project names no run window', () => {
    expect(runRetryBudget({})).toBe(RUN_SIGN_IN_RETRY_BUDGET_MS);
  });

  it('uses the run window the project names', () => {
    expect(runRetryBudget({ [RUN_RETRY_BUDGET_KEY]: 13_200_000 })).toBe(13_200_000);
  });

  it.each([0, -1, 1.5, '13200000', null])('refuses the run window %s', (budget) => {
    expect(() => runRetryBudget({ [RUN_RETRY_BUDGET_KEY]: budget })).toThrow('is invalid');
  });
});
