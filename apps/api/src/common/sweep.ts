import type { EntityManager, EntityTarget, ObjectLiteral } from 'typeorm';

/**
 * Caps a pathological backlog; the loop already drains on a short batch, so the
 * remainder simply waits for the next scheduled run.
 */
export const SWEEP_MAX_BATCHES = 1000;

export const DEFAULT_SWEEP_BATCH_SIZE = 1000;

/**
 * Ceiling on a configured batch size. One batch row-locks everything it
 * deletes, and a request-path delete over the same table waits behind it, so an
 * over-large batch turns a cleanup task into a stall.
 */
export const MAX_SWEEP_BATCH_SIZE = 10_000;

/**
 * Drive a batched delete until a short batch says nothing expired is left.
 * Every scheduled sweep shares this drain so the bound is one decision.
 */
export async function drainBatches(
  batchSize: number,
  deleteBatch: () => Promise<number>
): Promise<number> {
  let total = 0;
  for (let batch = 0; batch < SWEEP_MAX_BATCHES; batch += 1) {
    const deleted = await deleteBatch();
    total += deleted;
    if (deleted < batchSize) {
      break;
    }
  }
  return total;
}

/**
 * Delete the rows of `target` whose `expires_at` is at or before `cutoff`, in
 * batches of `batchSize`. Postgres has no `DELETE ... LIMIT`, so each batch
 * selects the `ctid`s under the cutoff and deletes exactly those; the
 * `expires_at` order lets the table's `expires_at` index drive the scan.
 * `SKIP LOCKED` yields any row that a request path or another instance's sweep
 * already deletes, so the two deletes take their row locks in any order
 * without a cycle.
 */
export function sweepExpiredRows(
  manager: EntityManager,
  target: EntityTarget<ObjectLiteral>,
  cutoff: Date,
  batchSize: number
): Promise<number> {
  // The subquery must name the table the outer `DELETE` does, schema included.
  const { connection } = manager;
  const table = connection
    .getMetadata(target)
    .tablePath.split('.')
    .map((part) => connection.driver.escape(part))
    .join('.');
  return drainBatches(batchSize, async () => {
    const result = await manager
      .createQueryBuilder()
      .delete()
      .from(target)
      .where(
        `ctid IN (SELECT ctid FROM ${table} WHERE expires_at <= :cutoff ORDER BY expires_at LIMIT :limit FOR UPDATE SKIP LOCKED)`,
        { cutoff, limit: batchSize }
      )
      .execute();
    return result.affected ?? 0;
  });
}
