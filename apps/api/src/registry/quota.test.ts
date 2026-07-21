import { describe, expect, it } from 'vitest';
import { byteConfigBigInt, DEFAULT_QUOTA_BYTES, exceedsQuota, resolveLimitBytes } from './quota';

/**
 * The quota arithmetic that gates uploads, proven exact in BigInt where a JS
 * `number` comparison would round (folded from #677). 2^53 is the first integer
 * `number` cannot represent alongside its neighbor — the boundary these tests
 * straddle.
 */
const TWO_POW_53 = 1n << 53n; // 9_007_199_254_740_992

describe('exceedsQuota — BigInt exactness across 2^53', () => {
  it('admits a use exactly at the limit and refuses one byte past it', () => {
    expect(exceedsQuota(900n, 100n, 1000n)).toBe(false); // sum 1000 == limit
    expect(exceedsQuota(901n, 100n, 1000n)).toBe(true); // sum 1001 > limit
    expect(exceedsQuota(0n, 1001n, 1000n)).toBe(true); // a single oversize upload
  });

  it('distinguishes limit and limit+1 above 2^53, where Number cannot', () => {
    const limit = TWO_POW_53 * 1000n; // ~9 PB, far past number precision
    // Exactly filling the limit is admitted...
    expect(exceedsQuota(limit - 1n, 1n, limit)).toBe(false);
    // ...and a single byte beyond is refused, even though both operands round
    // to the same JS number.
    expect(exceedsQuota(limit, 1n, limit)).toBe(true);
    expect(Number(limit) === Number(limit + 1n)).toBe(true);
  });

  it('gates a large incoming upload against a large existing use exactly', () => {
    const used = TWO_POW_53 + 5n;
    const incoming = TWO_POW_53 + 5n;
    const limit = 2n * TWO_POW_53 + 10n; // exactly used + incoming
    expect(exceedsQuota(used, incoming, limit)).toBe(false); // sum == limit
    expect(exceedsQuota(used, incoming, limit - 1n)).toBe(true); // sum == limit + 1
    expect(exceedsQuota(used, incoming + 1n, limit)).toBe(true); // sum == limit + 1
  });
});

describe('resolveLimitBytes', () => {
  it('prefers the per-account override, parsed exactly as BigInt', () => {
    const override = (TWO_POW_53 * 3n).toString();
    expect(resolveLimitBytes(override, DEFAULT_QUOTA_BYTES)).toBe(TWO_POW_53 * 3n);
  });

  it('falls back to the env default when there is no override', () => {
    expect(resolveLimitBytes(null, DEFAULT_QUOTA_BYTES)).toBe(DEFAULT_QUOTA_BYTES);
  });
});

describe('byteConfigBigInt', () => {
  it('parses a valid non-negative integer string exactly', () => {
    expect(byteConfigBigInt('1099511627776', 0n)).toBe(1099511627776n);
    const huge = TWO_POW_53 * 7n;
    expect(byteConfigBigInt(huge.toString(), 0n)).toBe(huge);
  });

  it('fails closed to the fallback for unset, empty, or garbage values', () => {
    expect(byteConfigBigInt(undefined, DEFAULT_QUOTA_BYTES)).toBe(DEFAULT_QUOTA_BYTES);
    expect(byteConfigBigInt('', DEFAULT_QUOTA_BYTES)).toBe(DEFAULT_QUOTA_BYTES);
    expect(byteConfigBigInt('not-a-number', DEFAULT_QUOTA_BYTES)).toBe(DEFAULT_QUOTA_BYTES);
    expect(byteConfigBigInt('12.5', DEFAULT_QUOTA_BYTES)).toBe(DEFAULT_QUOTA_BYTES);
    expect(byteConfigBigInt('-5', DEFAULT_QUOTA_BYTES)).toBe(DEFAULT_QUOTA_BYTES);
  });
});
