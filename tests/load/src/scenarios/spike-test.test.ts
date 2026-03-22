/**
 * Spike Test Scenario
 *
 * Starts with a baseline of 2 clients, then bursts to 20 clients.
 * Measures recovery time — how long until latencies return to baseline.
 */

import { describe, it, afterAll } from 'vitest';
import { createClientPool, destroyClientPool, type PoolClient } from '../harness/client-pool';
import { MetricsCollector } from '../harness/metrics';
import { printSummary, toJsonReport } from '../harness/reporter';
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

    const baselineStart = Date.now();
    await Promise.allSettled(
      baselinePool.map((pc) => {
        pc.metrics.start();
        return runFolderWorkload(pc, { cycles: BASELINE_CYCLES }).finally(() => pc.metrics.stop());
      })
    );
    const baselineDuration = Date.now() - baselineStart;

    const baselineMetrics = new MetricsCollector();
    baselineMetrics.start();
    for (const pc of baselinePool) {
      for (const sample of pc.metrics.getRawSamples()) {
        baselineMetrics.record(sample);
      }
    }
    baselineMetrics.stop();

    printSummary(
      'Spike Test - Baseline',
      baselineMetrics.getMetrics(),
      baselineDuration,
      BASELINE_CLIENTS
    );

    // Phase 2: Burst
    console.log('\n--- Phase 2: Burst ---');
    burstPool = await createClientPool({
      clientCount: BURST_CLIENTS,
      label: 'spike-burst',
    });

    const burstStart = Date.now();
    await Promise.allSettled(
      burstPool.map((pc) => {
        pc.metrics.start();
        return runFolderWorkload(pc, { cycles: BURST_CYCLES }).finally(() => pc.metrics.stop());
      })
    );
    const burstDuration = Date.now() - burstStart;

    const burstMetrics = new MetricsCollector();
    burstMetrics.start();
    for (const pc of burstPool) {
      for (const sample of pc.metrics.getRawSamples()) {
        burstMetrics.record(sample);
      }
    }
    burstMetrics.stop();

    printSummary('Spike Test - Burst', burstMetrics.getMetrics(), burstDuration, BURST_CLIENTS);

    // Compare baseline vs burst latencies
    const baselineOps = baselineMetrics.getMetrics();
    const burstOps = burstMetrics.getMetrics();

    console.log('\n--- Latency Comparison (p95) ---');
    for (const baseOp of baselineOps) {
      const burstOp = burstOps.find((b) => b.operation === baseOp.operation);
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

    // JSON for both phases
    console.log(
      '\nJSON Report (Burst):\n' +
        toJsonReport('spike-test-burst', burstOps, burstDuration, BURST_CLIENTS)
    );
  });
});
