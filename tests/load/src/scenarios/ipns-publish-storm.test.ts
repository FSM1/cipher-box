/**
 * IPNS Publish Storm Scenario
 *
 * N clients performing rapid folder mutations, each triggering IPNS publish.
 * Tests IPNS publish contention — the known system bottleneck.
 */

import { describe, it, afterAll, expect } from 'vitest';
import {
  createClientPool,
  destroyClientPool,
  aggregateAndReport,
  type PoolClient,
} from '../harness/client-pool';
import { checkThresholds, type ThresholdConfig } from '../harness/thresholds';
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

    const results = await Promise.allSettled(
      pool.map((pc) => {
        pc.metrics.start();
        return runFolderWorkload(pc, { cycles: CYCLES_PER_CLIENT }).finally(() =>
          pc.metrics.stop()
        );
      })
    );

    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    console.log(`\nClients completed: ${succeeded}/${pool.length}`);

    const metrics = await aggregateAndReport('IPNS Publish Storm', pool);

    // Threshold check: IPNS contention scenario, high variance expected
    const THRESHOLDS: ThresholdConfig[] = [
      { operation: 'createFolder', p95MaxMs: 10_000, errorRateMax: 0.1 },
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
