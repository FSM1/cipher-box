import { afterEach, describe, expect, it } from 'vitest';
import { resolveAuthLimit } from './throttling';

/**
 * The per-IP auth limit's test-profile override (#837). The deployed-profile
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
