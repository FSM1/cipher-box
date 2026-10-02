import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  DEVNET_BACKOFF_MS,
  devnetFault,
  markRunExhausted,
  nextStep,
  runExhausted,
  summarize,
} from './loginRetry';

const NONCE = 'could not retrieve nonce: Internal error';

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
  it('counts sign-ins, absorbed faults by class, and failures after all retries', () => {
    expect(
      summarize([
        { faults: [], result: 'signed-in' },
        { faults: [{ fault: 'nonce', attempt: 1 }], result: 'recovered' },
        {
          faults: [
            { fault: 'nonce', attempt: 1 },
            { fault: 'rss-round', attempt: 2 },
          ],
          result: 'exhausted',
        },
        { faults: [], result: 'refused' },
      ])
    ).toBe(
      'sign-ins: 4, recovered: 1, absorbed faults: nonce=2 rss-round=1, ' +
        'failed after all retries: 1, refused: 1'
    );
  });

  it('reads an empty run', () => {
    expect(summarize([])).toBe(
      'sign-ins: 0, recovered: 0, absorbed faults: none, failed after all retries: 0, refused: 0'
    );
  });
});

describe('nextStep', () => {
  it('fails at once on a refusal that is not a devnet fault', () => {
    expect(nextStep(0, 'the wallet signature was rejected', false)).toEqual({
      action: 'fail',
      fault: null,
      result: 'refused',
    });
  });

  it('retries a devnet fault with the backoff of its attempt', () => {
    DEVNET_BACKOFF_MS.forEach((waitMs, attempt) => {
      expect(nextStep(attempt, NONCE, false)).toEqual({ action: 'retry', fault: 'nonce', waitMs });
    });
  });

  it('stops after the last wait, on the fifth attempt', () => {
    expect(nextStep(DEVNET_BACKOFF_MS.length, NONCE, false)).toEqual({
      action: 'fail',
      fault: 'nonce',
      result: 'exhausted',
    });
  });

  it('does not wait in a run that has already exhausted the backoff', () => {
    expect(nextStep(0, NONCE, true)).toEqual({
      action: 'fail',
      fault: 'nonce',
      result: 'exhausted',
    });
  });
});

describe('run exhaustion state', () => {
  it('reads false until a sign-in marks it, and true after', () => {
    const root = mkdtempSync(join(tmpdir(), 'login-retry-'));
    const outputDir = join(root, 'test-results');
    try {
      expect(runExhausted(outputDir)).toBe(false);
      markRunExhausted(outputDir);
      expect(runExhausted(outputDir)).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
