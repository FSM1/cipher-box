import { afterEach, describe, expect, it } from 'vitest';
import { resolveAuthLimit, THROTTLE_SURFACES } from './throttling';

/** A surface's cap, whether the catalog fixes it or resolves it per request. */
function effectiveLimit(limit: number | (() => number)): number {
  return typeof limit === 'function' ? limit() : limit;
}

/**
 * The per-IP auth limit's test-profile override. The deployed-profile
 * refusal is the security-relevant half: it is what keeps the knob from being a
 * way to turn a live rate limit off.
 */
describe('resolveAuthLimit', () => {
  const original = { ...process.env };

  afterEach(() => {
    process.env = { ...original };
  });

  it('defaults to the catalog limit', () => {
    delete process.env.THROTTLE_AUTH_LIMIT;
    expect(resolveAuthLimit()).toBe(10);
  });

  it.each(['test', 'development'])('honors THROTTLE_AUTH_LIMIT on the %s profile', (nodeEnv) => {
    process.env.NODE_ENV = nodeEnv;
    process.env.THROTTLE_AUTH_LIMIT = '500';
    expect(resolveAuthLimit()).toBe(500);
  });

  it.each(['production', 'staging', undefined])(
    'refuses THROTTLE_AUTH_LIMIT on the deployed profile %s',
    (nodeEnv) => {
      if (nodeEnv === undefined) {
        delete process.env.NODE_ENV;
      } else {
        process.env.NODE_ENV = nodeEnv;
      }
      process.env.THROTTLE_AUTH_LIMIT = '500';
      expect(resolveAuthLimit()).toBe(10);
    }
  );

  it('falls back to the catalog limit on an unusable value', () => {
    process.env.NODE_ENV = 'test';
    process.env.THROTTLE_AUTH_LIMIT = 'lots';
    expect(resolveAuthLimit()).toBe(10);
  });
});

/**
 * The pre-reconstruction session mint is login-shaped and shares the auth
 * bucket's cap, so it has to share the resolver too: a suite that raises the
 * auth limit to run hot would otherwise still be throttled on this one route.
 */
describe('the deviceApprovalSession surface', () => {
  const original = { ...process.env };

  afterEach(() => {
    process.env = { ...original };
  });

  it('moves with the auth cap under the test-profile override', () => {
    process.env.NODE_ENV = 'test';
    process.env.THROTTLE_AUTH_LIMIT = '500';

    expect(effectiveLimit(THROTTLE_SURFACES.deviceApprovalSession.default.limit)).toBe(500);
  });

  it('holds the catalog limit on a deployed profile, where the override is refused', () => {
    process.env.NODE_ENV = 'production';
    process.env.THROTTLE_AUTH_LIMIT = '500';

    expect(effectiveLimit(THROTTLE_SURFACES.deviceApprovalSession.default.limit)).toBe(10);
  });
});
