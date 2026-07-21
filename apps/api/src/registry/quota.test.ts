import { describe, expect, it, vi } from 'vitest';
import type { Repository } from 'typeorm';
import {
  byteConfigBigInt,
  DEFAULT_QUOTA_BYTES,
  exceedsQuota,
  resolveLimitBytes,
  sumHostedBytes,
  sumPinnedBytes,
} from './quota';
import type { PinnedCid } from './entities/pinned-cid.entity';

/**
 * A minimal QueryBuilder double that records the `andWhere` clauses each sum
 * applies and returns a caller-set raw `used` string, so a test can prove which
 * rows a sum narrows to and that the driver's `numeric` string is read back as
 * an exact BigInt — without a live Postgres.
 */
function fakeRepo(used: string | undefined) {
  const andWhere = vi.fn().mockReturnThis();
  const qb = {
    select: vi.fn().mockReturnThis(),
    where: vi.fn().mockReturnThis(),
    andWhere,
    getRawOne: vi.fn().mockResolvedValue(used === undefined ? undefined : { used }),
  };
  const repo = {
    createQueryBuilder: vi.fn().mockReturnValue(qb),
  } as unknown as Repository<PinnedCid>;
  return { repo, qb, andWhere };
}

describe('sumPinnedBytes / sumHostedBytes — aggregation scope and BigInt read-back', () => {
  it('sumPinnedBytes sums ALL rows: no advisory predicate is applied', async () => {
    const { repo, andWhere } = fakeRepo('42');
    expect(await sumPinnedBytes(repo, 'acct-1')).toBe(42n);
    expect(andWhere).not.toHaveBeenCalled();
  });

  it('sumHostedBytes narrows to authoritative rows via advisory = false', async () => {
    const { repo, andWhere } = fakeRepo('42');
    expect(await sumHostedBytes(repo, 'acct-1')).toBe(42n);
    expect(andWhere).toHaveBeenCalledWith('pin.advisory = :advisory', { advisory: false });
  });

  it('reads the driver numeric string back as an exact BigInt above 2^53', async () => {
    const huge = ((1n << 53n) + 5n).toString();
    expect(await sumPinnedBytes(fakeRepo(huge).repo, 'acct-1')).toBe((1n << 53n) + 5n);
    expect(await sumHostedBytes(fakeRepo(huge).repo, 'acct-1')).toBe((1n << 53n) + 5n);
  });

  it('reads an empty account (no row / COALESCE 0) as 0n', async () => {
    expect(await sumPinnedBytes(fakeRepo(undefined).repo, 'acct-1')).toBe(0n);
    expect(await sumHostedBytes(fakeRepo('0').repo, 'acct-1')).toBe(0n);
  });
});

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
