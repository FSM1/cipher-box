/**
 * SDK IPNS Publish/Resolve Contention (Headless)
 *
 * Measures IPNS publish and resolve latency under concurrent load.
 * Isolates IPNS contention without upload or folder tree overhead.
 */
import { describe, it, afterAll } from 'vitest';
import {
  createClientPool,
  destroyClientPool,
  aggregateAndReport,
  type PoolClient,
} from '../harness/client-pool';
import { expectThresholdsPassed, type ThresholdConfig } from '../harness/thresholds';
import { prepareSdkClient, runIpnsPublishWorkload } from '../workloads/sdk-core-workload';

const NUM_CLIENTS = parseInt(process.env.LOAD_TEST_CLIENTS ?? '10', 10);
const CYCLES_PER_CLIENT = 15;

describe('SDK IPNS Contention (Headless)', () => {
  let pool: PoolClient[] = [];

  afterAll(async () => {
    await destroyClientPool(pool);
  });

  it(`${NUM_CLIENTS} clients x ${CYCLES_PER_CLIENT} publish/resolve cycles`, async () => {
    pool = await createClientPool({ clientCount: NUM_CLIENTS, label: 'sdk-ipns' });

    const results = await Promise.allSettled(
      pool.map((pc) => {
        pc.metrics.start();
        const swc = prepareSdkClient(pc);
        return runIpnsPublishWorkload(swc, {
          cycles: CYCLES_PER_CLIENT,
        }).finally(() => pc.metrics.stop());
      })
    );

    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    console.log(`\nClients completed: ${succeeded}/${pool.length}`);

    const metrics = await aggregateAndReport('SDK IPNS Contention', pool);

    const THRESHOLDS: ThresholdConfig[] = [
      { operation: 'sdkIpnsPublish', p95MaxMs: 5_000, errorRateMax: 0.1 },
      { operation: 'sdkIpnsResolve', p95MaxMs: 3_000, errorRateMax: 0.1 },
    ];

    expectThresholdsPassed(metrics, THRESHOLDS);
  });
});
