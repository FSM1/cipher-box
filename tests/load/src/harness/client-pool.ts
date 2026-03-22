/**
 * Load Test Client Pool
 *
 * Manages N CipherBoxClient instances, each with its own test account.
 * Creates accounts in parallel, distributes workloads, and collects metrics.
 *
 * Reuses the shared createTestAccount/deleteTestAccount from sdk-e2e
 * to avoid duplicating the 5-step account provisioning sequence.
 */

import { setApiClientConfig } from '@cipherbox/api-client';
import {
  createTestAccount,
  deleteTestAccount,
  type TestAccount,
} from '../../../sdk-e2e/src/fixtures/test-harness';
import { MetricsCollector, type OperationMetrics } from './metrics';
import { printSummary, toJsonReport } from './reporter';

const API_URL = process.env.LOAD_TEST_API_URL ?? 'http://localhost:3000';
const SECRET = process.env.LOAD_TEST_SECRET ?? 'e2e-test-secret-do-not-use-in-production';

export interface PoolClient extends TestAccount {
  id: number;
  metrics: MetricsCollector;
}

export interface ClientPoolOptions {
  clientCount: number;
  label: string;
}

/**
 * Create a pool of N authenticated CipherBoxClient instances.
 *
 * Each client has its own test account, vault, and metrics collector.
 * The api-client singleton is configured once (all clients share baseUrl,
 * tokens are per-request via getAccessToken closure).
 */
export async function createClientPool(opts: ClientPoolOptions): Promise<PoolClient[]> {
  const { clientCount, label } = opts;
  console.log(`Creating ${clientCount} test accounts for "${label}"...`);
  const start = performance.now();

  // Create accounts in parallel batches of 5 to avoid overwhelming the API
  const clients: PoolClient[] = [];
  const batchSize = 5;

  for (let batch = 0; batch < clientCount; batch += batchSize) {
    const batchEnd = Math.min(batch + batchSize, clientCount);
    const promises = [];

    for (let i = batch; i < batchEnd; i++) {
      promises.push(
        createTestAccount({
          apiUrl: API_URL,
          secret: SECRET,
          label: `${label}-${i}`,
          emailPrefix: 'load',
        }).then((account): PoolClient => ({ ...account, id: i, metrics: new MetricsCollector() }))
      );
    }

    const results = await Promise.allSettled(promises);
    for (const result of results) {
      if (result.status === 'fulfilled') {
        clients.push(result.value);
      } else {
        console.warn(`Failed to create pool client: ${result.reason}`);
      }
    }
  }

  // Configure the singleton once — all clients share the same baseUrl
  // Individual tokens are injected via the getAccessToken closure on each client
  if (clients.length > 0) {
    setApiClientConfig({
      baseUrl: API_URL,
      getAccessToken: async () => clients[0].accessToken,
    });
  }

  const elapsed = performance.now() - start;
  console.log(
    `Created ${clients.length}/${clientCount} clients in ${(elapsed / 1000).toFixed(1)}s`
  );

  return clients;
}

/**
 * Destroy all clients in the pool and delete test accounts.
 */
export async function destroyClientPool(pool: PoolClient[]): Promise<void> {
  console.log(`Cleaning up ${pool.length} test accounts...`);
  for (const pc of pool) {
    pc.client.destroy();
    await deleteTestAccount(pc, API_URL);
  }
}

/**
 * Aggregate metrics from all pool clients, print summary, and return metrics.
 * Extracts the repeated boilerplate from every load test scenario.
 */
export async function aggregateAndReport(
  scenarioName: string,
  pool: PoolClient[]
): Promise<OperationMetrics[]> {
  const allMetrics = new MetricsCollector();

  let minTimestamp = Infinity;
  let maxTimestamp = 0;

  for (const pc of pool) {
    for (const sample of pc.metrics.getReadonlySamples()) {
      allMetrics.record(sample);
      if (sample.timestamp < minTimestamp) minTimestamp = sample.timestamp;
      if (sample.timestamp > maxTimestamp) maxTimestamp = sample.timestamp;
    }
  }

  // Set collector timing from sample timestamps for accurate throughput calculation
  allMetrics.setElapsedMs(maxTimestamp > minTimestamp ? maxTimestamp - minTimestamp : 1);

  const totalDuration = maxTimestamp > minTimestamp ? maxTimestamp - minTimestamp : 0;
  const metrics = allMetrics.getMetrics();

  printSummary(scenarioName, metrics, totalDuration, pool.length);

  // Write JSON report to file for CI artifact upload
  const reportJson = toJsonReport(scenarioName, metrics, totalDuration, pool.length);
  console.log('\nJSON Report:\n' + reportJson);

  try {
    const fs = await import('node:fs/promises');
    const slug = scenarioName.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    await fs.writeFile(`metrics-${slug}.json`, reportJson);
  } catch {
    // Non-fatal — CI artifact upload will just find no files
  }

  return metrics;
}
