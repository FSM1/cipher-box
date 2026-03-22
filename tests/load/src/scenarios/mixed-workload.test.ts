/**
 * Mixed Workload Scenario
 *
 * Simulates realistic usage: folder CRUD, file uploads, renames, moves, deletes
 * with weighted probabilities. Tests the system under representative load.
 */

import { describe, it, afterAll } from 'vitest';
import { createClientPool, destroyClientPool, type PoolClient } from '../harness/client-pool';
import { MetricsCollector } from '../harness/metrics';
import { printSummary, toJsonReport } from '../harness/reporter';
import { runMixedWorkload } from '../workloads/mixed-workload';

const NUM_CLIENTS = parseInt(process.env.LOAD_TEST_CLIENTS ?? '5', 10);
const OPS_PER_CLIENT = 45;

describe('Mixed Workload', () => {
  let pool: PoolClient[] = [];

  afterAll(async () => {
    await destroyClientPool(pool);
  });

  it(`${NUM_CLIENTS} clients × ${OPS_PER_CLIENT} mixed ops`, async () => {
    pool = await createClientPool({
      clientCount: NUM_CLIENTS,
      label: 'mixed',
    });

    const results = await Promise.allSettled(
      pool.map((pc) => {
        pc.metrics.start();
        return runMixedWorkload(pc, {
          totalOps: OPS_PER_CLIENT,
          weights: {
            createFolder: 2,
            uploadFile: 4,
            renameItem: 1,
            moveItem: 1,
            deleteItem: 1,
          },
        }).finally(() => pc.metrics.stop());
      })
    );

    // Aggregate
    const allMetrics = new MetricsCollector();
    allMetrics.start();
    for (const pc of pool) {
      for (const sample of pc.metrics.getRawSamples()) {
        allMetrics.record(sample);
      }
    }
    allMetrics.stop();

    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    console.log(`\nClients completed: ${succeeded}/${pool.length}`);

    const metrics = allMetrics.getMetrics();
    const samples = pool.flatMap((pc) => pc.metrics.getRawSamples());
    const totalDuration =
      samples.length > 0
        ? Math.max(...samples.map((s) => s.timestamp)) -
          Math.min(...samples.map((s) => s.timestamp))
        : 0;

    printSummary('Mixed Workload', metrics, totalDuration, pool.length);
    console.log(
      '\nJSON Report:\n' + toJsonReport('mixed-workload', metrics, totalDuration, pool.length)
    );
  });
});
