/**
 * Sustained Load Scenario
 *
 * N clients running at a steady rate for a configurable duration.
 * Tests latency stability over time — detects memory leaks, connection
 * pool exhaustion, and other time-dependent degradation.
 */

import { describe, it, afterAll } from 'vitest';
import {
  createClientPool,
  destroyClientPool,
  aggregateAndReport,
  type PoolClient,
} from '../harness/client-pool';
import { expectThresholdsPassed, type ThresholdConfig } from '../harness/thresholds';

const NUM_CLIENTS = parseInt(process.env.LOAD_TEST_CLIENTS ?? '5', 10);
const DURATION_SEC = parseInt(process.env.LOAD_TEST_DURATION ?? '300', 10);
const OPS_PER_SEC_PER_CLIENT = 2;

describe('Sustained Load', () => {
  let pool: PoolClient[] = [];

  afterAll(async () => {
    await destroyClientPool(pool);
  });

  it(`${NUM_CLIENTS} clients × ${OPS_PER_SEC_PER_CLIENT} ops/sec for ${DURATION_SEC}s`, async () => {
    pool = await createClientPool({
      clientCount: NUM_CLIENTS,
      label: 'sustained',
    });

    const endTime = Date.now() + DURATION_SEC * 1000;

    const results = await Promise.allSettled(
      pool.map((pc) => runSustainedClient(pc, endTime, OPS_PER_SEC_PER_CLIENT))
    );

    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    console.log(`\nClients completed: ${succeeded}/${pool.length}`);

    const metrics = await aggregateAndReport('Sustained Load', pool);

    // Threshold check: same as upload-throughput for sustained operations
    const THRESHOLDS: ThresholdConfig[] = [
      { operation: 'uploadFile', p95MaxMs: 10_000, errorRateMax: 0.05 },
      { operation: 'createFolder', p95MaxMs: 5_000, errorRateMax: 0.05 },
    ];

    expectThresholdsPassed(metrics, THRESHOLDS);
  });
});

async function runSustainedClient(
  pc: PoolClient,
  endTime: number,
  opsPerSec: number
): Promise<void> {
  const { client, rootIpnsName, metrics } = pc;
  metrics.start();

  const intervalMs = 1000 / opsPerSec;
  let folderCounter = 0;

  while (Date.now() < endTime) {
    const opStart = Date.now();

    try {
      // Alternate between folder create and delete to keep state manageable
      const name = `sustained-${pc.id}-${folderCounter++}`;

      const folder = await metrics.measure('createFolder', () =>
        client.createFolder(rootIpnsName, name)
      );

      // Small file upload
      const data = new Uint8Array(1024);
      crypto.getRandomValues(data);
      await metrics.measure(
        'uploadFile',
        () => client.uploadFile(rootIpnsName, data, `${name}.bin`, 'application/octet-stream'),
        1024
      );

      // Cleanup to prevent state bloat
      const folderState = client.getFolderTree().get(rootIpnsName);
      const fileChild = folderState?.children.find((c) => c.name === `${name}.bin`);
      if (fileChild) {
        await metrics.measure('deleteItem', () => client.deleteItem(rootIpnsName, fileChild.id));
      }
      await metrics.measure('deleteItem', () => client.deleteItem(rootIpnsName, folder.id));
    } catch {
      // Non-fatal — continue the sustained load
    }

    // Wait for next interval
    const elapsed = Date.now() - opStart;
    const wait = Math.max(0, intervalMs - elapsed);
    if (wait > 0) {
      await new Promise((r) => setTimeout(r, wait));
    }
  }

  metrics.stop();
}
