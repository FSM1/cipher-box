/**
 * SDK Upload Pipeline (Headless)
 *
 * Measures encrypt + IPFS pin + IPNS metadata publish latency
 * using direct sdk-core calls without CipherBoxClient folder tree overhead.
 */
import { describe, it, afterAll } from 'vitest';
import {
  createClientPool,
  destroyClientPool,
  aggregateAndReport,
  type PoolClient,
} from '../harness/client-pool';
import { expectThresholdsPassed, type ThresholdConfig } from '../harness/thresholds';
import { prepareSdkClient, runUploadPipelineWorkload } from '../workloads/sdk-core-workload';

const NUM_CLIENTS = parseInt(process.env.LOAD_TEST_CLIENTS ?? '5', 10);
const FILES_PER_CLIENT = 10;
const FILE_SIZE = 10_000; // 10KB

describe('SDK Upload Pipeline (Headless)', () => {
  let pool: PoolClient[] = [];

  afterAll(async () => {
    await destroyClientPool(pool);
  });

  it(`${NUM_CLIENTS} clients x ${FILES_PER_CLIENT} files (${FILE_SIZE}B each)`, async () => {
    pool = await createClientPool({ clientCount: NUM_CLIENTS, label: 'sdk-upload' });

    const results = await Promise.allSettled(
      pool.map((pc) => {
        pc.metrics.start();
        const swc = prepareSdkClient(pc);
        return runUploadPipelineWorkload(swc, {
          fileCount: FILES_PER_CLIENT,
          fileSizeBytes: FILE_SIZE,
        }).finally(() => pc.metrics.stop());
      })
    );

    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    console.log(`\nClients completed: ${succeeded}/${pool.length}`);

    const metrics = await aggregateAndReport('SDK Upload Pipeline', pool);

    const THRESHOLDS: ThresholdConfig[] = [
      { operation: 'sdkUploadFile', p95MaxMs: 10_000, errorRateMax: 0.1 },
    ];

    expectThresholdsPassed(metrics, THRESHOLDS);
  });
});
