import { Repository, SelectQueryBuilder } from 'typeorm';
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
 * Per-account `COALESCE(SUM(size), 0)` aggregate, exact at any magnitude.
 * Postgres returns the `bigint` sum as `numeric` (a driver STRING), so
 * `BigInt(...)` preserves precision that TypeORM's `sum()` — which returns a
 * lossy JS `number` and can only type numeric columns — would drop above 2^53
 * bytes (folded from #677). `COALESCE(..., 0)` makes an empty account read 0.
 * `narrow` optionally restricts the summed rows.
 */
async function sumSizeBytes(
  repo: Repository<PinnedCid>,
  accountId: string,
  narrow?: (qb: SelectQueryBuilder<PinnedCid>) => void
): Promise<bigint> {
  const qb = repo
    .createQueryBuilder('pin')
    .select('COALESCE(SUM(pin.size), 0)', 'used')
    .where('pin.account_id = :accountId', { accountId });
  narrow?.(qb);
  const row = await qb.getRawOne<{ used: string }>();
  return BigInt(row?.used ?? '0');
}

/**
 * The rows the hosted quota counts. Written ONCE and shared by the gate sum and
 * the reported sum: #843 was two callers disagreeing about which rows count, so
 * the predicate must not be re-typed per query.
 */
const HOSTED_ROWS = 'pin.advisory = false';

/**
 * The quota-GATE sum: only AUTHORITATIVE hosted rows. BYO/advisory bytes live
 * on the user's own provider and never count against the hosted quota
 * (blueprint/api.md, Registry: "Hosted rows are authoritative and gate uploads;
 * BYO accounts' rows are advisory — quota always allows"), so a hosted upload
 * must not be 413'd by stale advisory rows an account kept after toggling BYO
 * off.
 */
export function sumHostedBytes(repo: Repository<PinnedCid>, accountId: string): Promise<bigint> {
  return sumSizeBytes(repo, accountId, (qb) => qb.andWhere(HOSTED_ROWS));
}

/** The pair `GET /account/quota` reports: the gated sum and the all-rows sum. */
export interface QuotaSums {
  /** The GATED sum — the same rows `sumHostedBytes` gives the upload gate. */
  hosted: bigint;
  /** Every pin row, advisory included. Informational; never gated. */
  pinned: bigint;
}

/**
 * Both sums in ONE aggregate: one round trip on a polled endpoint, and one MVCC
 * snapshot, so `pinned >= hosted` holds by construction rather than by luck of
 * two interleaved reads.
 */
export async function quotaSums(
  repo: Repository<PinnedCid>,
  accountId: string
): Promise<QuotaSums> {
  const row = await repo
    .createQueryBuilder('pin')
    .select(`COALESCE(SUM(pin.size) FILTER (WHERE ${HOSTED_ROWS}), 0)`, 'hosted')
    .addSelect('COALESCE(SUM(pin.size), 0)', 'pinned')
    .where('pin.account_id = :accountId', { accountId })
    .getRawOne<{ hosted: string; pinned: string }>();
  return { hosted: BigInt(row?.hosted ?? '0'), pinned: BigInt(row?.pinned ?? '0') };
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
