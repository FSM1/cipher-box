/**
 * Upload Throughput Scenario
 *
 * N clients each upload M files (1KB-500KB), measuring upload pipeline
 * throughput including IPNS publish per file.
 */

import { describe, it, afterAll } from 'vitest';
import { createClientPool, destroyClientPool, type PoolClient } from '../harness/client-pool';
import { MetricsCollector } from '../harness/metrics';
import { printSummary, toJsonReport } from '../harness/reporter';
import { runFileWorkload } from '../workloads/file-workload';

const NUM_CLIENTS = parseInt(process.env.LOAD_TEST_CLIENTS ?? '10', 10);
const FILES_PER_CLIENT = 20;

describe('Upload Throughput', () => {
  let pool: PoolClient[] = [];

  afterAll(async () => {
    await destroyClientPool(pool);
  });

  it(`${NUM_CLIENTS} clients × ${FILES_PER_CLIENT} files (1KB-500KB)`, async () => {
    pool = await createClientPool({
      clientCount: NUM_CLIENTS,
      label: 'upload-throughput',
    });

    const globalMetrics = new MetricsCollector();
    globalMetrics.start();

    // Run all client workloads concurrently
    const results = await Promise.allSettled(
      pool.map((pc) => {
        pc.metrics.start();
        return runFileWorkload(pc, {
          fileCount: FILES_PER_CLIENT,
          minSize: 1_024,
          maxSize: 500 * 1_024,
          verifyDownloads: false,
        }).finally(() => pc.metrics.stop());
      })
    );

    globalMetrics.stop();

    // Aggregate metrics from all clients
    const allMetrics = new MetricsCollector();
    allMetrics.start();
    for (const pc of pool) {
      for (const sample of pc.metrics.getRawSamples()) {
        allMetrics.record(sample);
      }
    }
    allMetrics.stop();

    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.filter((r) => r.status === 'rejected').length;
    console.log(`\nClients completed: ${succeeded} succeeded, ${failed} failed`);

    const metrics = allMetrics.getMetrics();
    const totalDuration =
      Math.max(...pool.map((pc) => pc.metrics.getRawSamples().at(-1)?.timestamp ?? 0)) -
      Math.min(...pool.map((pc) => pc.metrics.getRawSamples()[0]?.timestamp ?? Date.now()));

    printSummary('Upload Throughput', metrics, totalDuration, pool.length);

    // Write JSON report
    const json = toJsonReport('upload-throughput', metrics, totalDuration, pool.length);
    console.log('\nJSON Report:\n' + json);
  });
});
