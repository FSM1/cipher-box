import { Repository } from 'typeorm';
import { PinnedCid } from './entities/pinned-cid.entity';

/** Default per-account quota when neither an override nor `QUOTA_DEFAULT_BYTES` is set: 10 GiB. */
export const DEFAULT_QUOTA_BYTES = 10n * 1024n * 1024n * 1024n;

/**
 * Read a non-negative integer byte bound from config as a BigInt, failing
 * closed to the fallback for an unset OR garbage value. BigInt (not Number)
 * so an override above 2^53 bytes is honored exactly.
 */
export function byteConfigBigInt(raw: unknown, fallback: bigint): bigint {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return fallback;
  }
  try {
    const value = BigInt(String(raw).trim());
    return value >= 0n ? value : fallback;
  } catch {
    return fallback;
  }
}

/**
 * Server-side `SUM(size)` over the account's pin rows, exact at any magnitude.
 * Postgres returns the `bigint` sum as `numeric` (a driver STRING), so
 * `BigInt(...)` preserves precision that TypeORM's `sum()` — which returns a
 * lossy JS `number` and can only type numeric columns — would drop above 2^53
 * bytes (folded from #677). `COALESCE(..., 0)` makes an empty account read 0.
 */
export async function sumPinnedBytes(
  repo: Repository<PinnedCid>,
  accountId: string
): Promise<bigint> {
  const row = await repo
    .createQueryBuilder('pin')
    .select('COALESCE(SUM(pin.size), 0)', 'used')
    .where('pin.account_id = :accountId', { accountId })
    .getRawOne<{ used: string }>();
  return BigInt(row?.used ?? '0');
}

/** The account limit in bytes: the per-account override, else the env default. */
export function resolveLimitBytes(
  quotaLimitOverride: string | null,
  defaultLimitBytes: bigint
): bigint {
  return quotaLimitOverride != null ? BigInt(quotaLimitOverride) : defaultLimitBytes;
}

/**
 * The over-quota decision, exact at any magnitude — BigInt throughout so a large
 * account gates correctly where a JS `number` comparison would round (#677).
 */
export function exceedsQuota(used: bigint, incoming: bigint, limit: bigint): boolean {
  return used + incoming > limit;
}
