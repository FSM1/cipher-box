import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  DEVNET_BACKOFF_MS,
  devnetFault,
  nextStep,
  SIGN_IN_RETRY_BUDGET_MS,
  runRetryDeadline,
  RUN_SIGN_IN_RETRY_BUDGET_MS,
  summarize,
} from './loginRetry';

const NONCE = 'could not retrieve nonce: Internal error';
const RUN_LEFT = RUN_SIGN_IN_RETRY_BUDGET_MS;

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

describe('DEVNET_BACKOFF_MS', () => {
  it('grows and spans 3 to 4 minutes', () => {
    const total = DEVNET_BACKOFF_MS.reduce((sum, wait) => sum + wait, 0);
    expect(total).toBeGreaterThanOrEqual(180_000);
    expect(total).toBeLessThanOrEqual(240_000);
    for (let i = 1; i < DEVNET_BACKOFF_MS.length; i += 1) {
      expect(DEVNET_BACKOFF_MS[i]).toBeGreaterThan(DEVNET_BACKOFF_MS[i - 1]!);
    }
  });
});

describe('summarize', () => {
  it('distinguishes terminal faults, attempt exhaustion and the two time limits', () => {
    expect(
      summarize([
        { faults: [], result: 'signed-in' },
        { faults: [{ fault: 'nonce', attempt: 1 }], result: 'recovered' },
        {
          faults: [
            { fault: 'nonce', attempt: 1 },
            { fault: 'rss-round', attempt: 2 },
          ],
          result: 'attempts-exhausted',
        },
        { faults: [], result: 'refused' },
        { faults: [{ fault: 'node-5xx', attempt: 1 }], result: 'run-budget' },
        { faults: [{ fault: 'node-busy', attempt: 2 }], result: 'sign-in-budget' },
      ])
    ).toBe(
      'sign-ins: 6, recovered: 1, observed faults: nonce=2 rss-round=1 node-5xx=1 node-busy=1, ' +
        'attempts exhausted: 1, sign-in budget exhausted: 1, ' +
        'retries suppressed by run budget: 1, refused: 1'
    );
  });

  it('reads an empty run', () => {
    expect(summarize([])).toBe(
      'sign-ins: 0, recovered: 0, observed faults: none, attempts exhausted: 0, ' +
        'sign-in budget exhausted: 0, retries suppressed by run budget: 0, refused: 0'
    );
  });
});

describe('nextStep', () => {
  it('fails at once on a refusal that is not a devnet fault', () => {
    expect(nextStep(0, 'the wallet signature was rejected', RUN_LEFT, 0)).toEqual({
      action: 'fail',
      fault: null,
      result: 'refused',
    });
  });

  it('retries a devnet fault with the backoff of its attempt', () => {
    DEVNET_BACKOFF_MS.forEach((waitMs, attempt) => {
      expect(nextStep(attempt, NONCE, RUN_LEFT, 0)).toEqual({
        action: 'retry',
        fault: 'nonce',
        waitMs,
      });
    });
  });

  it('stops after the last wait, on the fifth attempt', () => {
    expect(nextStep(DEVNET_BACKOFF_MS.length, NONCE, RUN_LEFT, 0)).toEqual({
      action: 'fail',
      fault: 'nonce',
      result: 'attempts-exhausted',
    });
  });

  it('reports run-budget suppression separately from attempt exhaustion', () => {
    expect(nextStep(0, NONCE, 0, 0)).toEqual({
      action: 'fail',
      fault: 'nonce',
      result: 'run-budget',
    });
  });
});

describe('nextStep budget', () => {
  it('retries while the wait still fits in the budget of one sign-in', () => {
    const waitMs = DEVNET_BACKOFF_MS[1]!;
    expect(nextStep(1, NONCE, RUN_LEFT, SIGN_IN_RETRY_BUDGET_MS - waitMs - 1)).toEqual({
      action: 'retry',
      fault: 'nonce',
      waitMs,
    });
  });

  it('stops at the sign-in limit when a wait leaves no time for the next attempt', () => {
    const waitMs = DEVNET_BACKOFF_MS[1]!;
    expect(nextStep(1, NONCE, RUN_LEFT, SIGN_IN_RETRY_BUDGET_MS - waitMs)).toEqual({
      action: 'fail',
      fault: 'nonce',
      result: 'sign-in-budget',
    });
  });

  it('does not start a wait that consumes the remaining run window', () => {
    const waitMs = DEVNET_BACKOFF_MS[0]!;
    expect(nextStep(0, NONCE, waitMs, 0)).toMatchObject({ action: 'fail', result: 'run-budget' });
    expect(nextStep(0, NONCE, waitMs + 1, 0)).toMatchObject({ action: 'retry', waitMs });
  });
});

describe('the retry window across logins and workers', () => {
  it('allows a later login to retry after an earlier login exhausts its attempts', () => {
    const root = mkdtempSync(join(tmpdir(), 'login-retry-'));
    const outputDir = join(root, 'test-results');
    const now = 1_000_000;
    try {
      const deadline = runRetryDeadline(outputDir, now);
      expect(deadline).toBe(now + RUN_SIGN_IN_RETRY_BUDGET_MS);
      expect(nextStep(4, NONCE, deadline - now, 240_000)).toMatchObject({
        action: 'fail',
        result: 'attempts-exhausted',
      });
      // A replacement worker reads the same file, with no state from the failed login.
      const later = now + 300_000;
      const laterDeadline = runRetryDeadline(outputDir, later);
      expect(laterDeadline).toBe(deadline);
      expect(nextStep(0, NONCE, laterDeadline - later, 0)).toMatchObject({ action: 'retry' });
      expect(nextStep(0, NONCE, laterDeadline - (deadline + 1), 0)).toMatchObject({
        action: 'fail',
        result: 'run-budget',
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('refuses corrupt persisted state instead of silently granting a new window', () => {
    const root = mkdtempSync(join(tmpdir(), 'login-retry-'));
    try {
      runRetryDeadline(root, 1_000_000);
      writeFileSync(join(root, 'devnet-retry-deadline'), 'not a deadline');
      expect(() => runRetryDeadline(root, 2_000_000)).toThrow('retry deadline is invalid');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
