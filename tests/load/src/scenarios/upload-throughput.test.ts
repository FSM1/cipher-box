/**
 * Upload Throughput Scenario
 *
 * N clients each upload M files (1KB-500KB), measuring upload pipeline
 * throughput including IPNS publish per file.
 */

import { describe, it, afterAll, expect } from 'vitest';
import {
  createClientPool,
  destroyClientPool,
  aggregateAndReport,
  type PoolClient,
} from '../harness/client-pool';
import { checkThresholds, type ThresholdConfig } from '../harness/thresholds';
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

    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.filter((r) => r.status === 'rejected').length;
    console.log(`\nClients completed: ${succeeded} succeeded, ${failed} failed`);

    const metrics = await aggregateAndReport('Upload Throughput', pool);

    // Threshold check: 2-3x observed baselines from Phase 19.2
    const THRESHOLDS: ThresholdConfig[] = [
      { operation: 'uploadFile', p95MaxMs: 10_000, errorRateMax: 0.05 },
    ];

    const thresholdResult = checkThresholds(metrics, THRESHOLDS);
    if (!thresholdResult.passed) {
      console.warn('THRESHOLD VIOLATIONS:');
      thresholdResult.violations.forEach((v) => console.warn(`  - ${v}`));
    }
    expect(
      thresholdResult.passed,
      `Threshold violations:\n${thresholdResult.violations.join('\n')}`
    ).toBe(true);
  });
});
