import { describe, expect, it } from 'vitest';
import { DEVNET_BACKOFF_MS, isDevnetFault } from './loginRetry';

describe('isDevnetFault', () => {
  it.each([
    'could not retrieve nonce: Internal error, failed to get nonce with status code: 503',
    'Cannot perform rss round 1',
    'master poly commits inconsistent with tssPubKey',
    'Unable to resolve enough promises',
    'the request to node-1.dev-node.web3auth.io failed with status 500',
  ])('retries %s', (refusal) => {
    expect(isDevnetFault(refusal)).toBe(true);
  });

  it.each([
    'the wallet signature was rejected',
    'the request to api.example.com failed with status 500',
    'the request to node-1.dev-node.web3auth.io failed with status 401',
  ])('fails at once on %s', (refusal) => {
    expect(isDevnetFault(refusal)).toBe(false);
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
