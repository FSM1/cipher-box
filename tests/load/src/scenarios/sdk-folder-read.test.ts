/**
 * SDK Folder Read Path (Headless)
 *
 * Measures IPNS resolve + IPFS fetch + decrypt latency for folder metadata.
 * Isolates the read path without write operations or client state.
 */
import { describe, it, afterAll } from 'vitest';
import {
  createClientPool,
  destroyClientPool,
  aggregateAndReport,
  type PoolClient,
} from '../harness/client-pool';
import { expectThresholdsPassed, type ThresholdConfig } from '../harness/thresholds';
import { prepareSdkClient, runFolderReadWorkload } from '../workloads/sdk-core-workload';

const NUM_CLIENTS = parseInt(process.env.LOAD_TEST_CLIENTS ?? '5', 10);
const CYCLES_PER_CLIENT = 20;

describe('SDK Folder Read (Headless)', () => {
  let pool: PoolClient[] = [];

  afterAll(async () => {
    await destroyClientPool(pool);
  });

  it(`${NUM_CLIENTS} clients x ${CYCLES_PER_CLIENT} folder read cycles`, async () => {
    pool = await createClientPool({ clientCount: NUM_CLIENTS, label: 'sdk-folder-read' });

    const results = await Promise.allSettled(
      pool.map((pc) => {
        pc.metrics.start();
        const swc = prepareSdkClient(pc);
        return runFolderReadWorkload(swc, {
          cycles: CYCLES_PER_CLIENT,
        }).finally(() => pc.metrics.stop());
      })
    );

    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    console.log(`\nClients completed: ${succeeded}/${pool.length}`);

    const metrics = await aggregateAndReport('SDK Folder Read', pool);

    const THRESHOLDS: ThresholdConfig[] = [
      { operation: 'sdkFolderRead', p95MaxMs: 4_000, errorRateMax: 0.1 },
    ];

    expectThresholdsPassed(metrics, THRESHOLDS);
  });
});
