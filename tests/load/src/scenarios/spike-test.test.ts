/**
 * Spike Test Scenario
 *
 * Starts with a baseline of 2 clients, then bursts to 20 clients.
 * Measures recovery time — how long until latencies return to baseline.
 */

import { describe, it, afterAll } from 'vitest';
import {
  createClientPool,
  destroyClientPool,
  aggregateAndReport,
  type PoolClient,
} from '../harness/client-pool';
import { expectThresholdsPassed, type ThresholdConfig } from '../harness/thresholds';
import { runFolderWorkload } from '../workloads/folder-workload';

const BASELINE_CLIENTS = 2;
const BURST_CLIENTS = parseInt(process.env.LOAD_TEST_CLIENTS ?? '20', 10);
const BASELINE_CYCLES = 10;
const BURST_CYCLES = 30;

describe('Spike Test', () => {
  let baselinePool: PoolClient[] = [];
  let burstPool: PoolClient[] = [];

  afterAll(async () => {
    await destroyClientPool(baselinePool);
    await destroyClientPool(burstPool);
  });

  it(`baseline ${BASELINE_CLIENTS} clients → burst ${BURST_CLIENTS} clients`, async () => {
    // Phase 1: Baseline
    console.log('\n--- Phase 1: Baseline ---');
    baselinePool = await createClientPool({
      clientCount: BASELINE_CLIENTS,
      label: 'spike-baseline',
    });

    await Promise.allSettled(
      baselinePool.map((pc) => {
        pc.metrics.start();
        return runFolderWorkload(pc, { cycles: BASELINE_CYCLES }).finally(() => pc.metrics.stop());
      })
    );

    const baselineMetrics = await aggregateAndReport('Spike Test - Baseline', baselinePool);

    // Phase 2: Burst
    console.log('\n--- Phase 2: Burst ---');
    burstPool = await createClientPool({
      clientCount: BURST_CLIENTS,
      label: 'spike-burst',
    });

    await Promise.allSettled(
      burstPool.map((pc) => {
        pc.metrics.start();
        return runFolderWorkload(pc, { cycles: BURST_CYCLES }).finally(() => pc.metrics.stop());
      })
    );

    const burstMetrics = await aggregateAndReport('Spike Test - Burst', burstPool);

    // Compare baseline vs burst latencies
    console.log('\n--- Latency Comparison (p95) ---');
    for (const baseOp of baselineMetrics) {
      const burstOp = burstMetrics.find((b) => b.operation === baseOp.operation);
      if (burstOp) {
        const degradation = (
          ((burstOp.latency.p95 - baseOp.latency.p95) / baseOp.latency.p95) *
          100
        ).toFixed(0);
        console.log(
          `  ${baseOp.operation}: baseline=${Math.round(baseOp.latency.p95)}ms → burst=${Math.round(burstOp.latency.p95)}ms (${degradation}% change)`
        );
      }
    }

    // Threshold check on burst phase: generous limits for intentional overload
    const THRESHOLDS: ThresholdConfig[] = [
      { operation: 'uploadFile', p95MaxMs: 15_000, errorRateMax: 0.15 },
      { operation: 'createFolder', p95MaxMs: 15_000, errorRateMax: 0.15 },
    ];

    expectThresholdsPassed(burstMetrics, THRESHOLDS);
  });
});
