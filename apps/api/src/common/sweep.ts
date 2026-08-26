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
 * Every scheduled sweep shares this drain so the bound is one decision; each
 * caller keeps its own statement, where its table and index rationale lives.
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
