/**
 * IPNS Publish Storm Scenario
 *
 * N clients performing rapid folder mutations, each triggering IPNS publish.
 * Tests IPNS publish contention — the known system bottleneck.
 */

import { describe, it, afterAll } from 'vitest';
import { createClientPool, destroyClientPool, type PoolClient } from '../harness/client-pool';
import { MetricsCollector } from '../harness/metrics';
import { printSummary, toJsonReport } from '../harness/reporter';
import { runFolderWorkload } from '../workloads/folder-workload';

const NUM_CLIENTS = parseInt(process.env.LOAD_TEST_CLIENTS ?? '20', 10);
const CYCLES_PER_CLIENT = 50;

describe('IPNS Publish Storm', () => {
  let pool: PoolClient[] = [];

  afterAll(async () => {
    await destroyClientPool(pool);
  });

  it(`${NUM_CLIENTS} clients × ${CYCLES_PER_CLIENT} folder create-rename-delete cycles`, async () => {
    pool = await createClientPool({
      clientCount: NUM_CLIENTS,
      label: 'ipns-storm',
    });

    // Run all client workloads concurrently
    const results = await Promise.allSettled(
      pool.map((pc) => {
        pc.metrics.start();
        return runFolderWorkload(pc, { cycles: CYCLES_PER_CLIENT }).finally(() =>
          pc.metrics.stop()
        );
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

    printSummary('IPNS Publish Storm', metrics, totalDuration, pool.length);
    console.log(
      '\nJSON Report:\n' + toJsonReport('ipns-publish-storm', metrics, totalDuration, pool.length)
    );
  });
});
