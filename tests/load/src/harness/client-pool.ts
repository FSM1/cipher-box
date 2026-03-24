/**
 * Load Test Client Pool
 *
 * Manages N CipherBoxClient instances, each with its own test account.
 * Creates accounts in parallel, distributes workloads, and collects metrics.
 *
 * Reuses the shared createTestAccount/deleteTestAccount from sdk-e2e
 * to avoid duplicating the 5-step account provisioning sequence.
 */

import {
  createTestAccount,
  deleteTestAccount,
  type TestAccount,
} from '../../../sdk-e2e/src/fixtures/test-harness';
import { MetricsCollector, type OperationMetrics } from './metrics';
import { printSummary, toJsonReport } from './reporter';
import {
  KuboProvider,
  PsaProvider,
  type PinningProvider,
  type PinningMode,
  type ExternalProviderConfig,
} from '@cipherbox/sdk-core';

const API_URL = process.env.LOAD_TEST_API_URL ?? 'http://localhost:3000';
const SECRET = process.env.LOAD_TEST_SECRET ?? 'e2e-test-secret-do-not-use-in-production';

/** BYO external provider config from environment variables */
export const BYO_ENDPOINT = process.env.BYO_IPFS_ENDPOINT; // e.g., https://api.pinata.cloud/psa
export const BYO_AUTH_TOKEN = process.env.BYO_IPFS_AUTH_TOKEN ?? '';
export const BYO_PROTOCOL = (process.env.BYO_IPFS_PROTOCOL ?? 'kubo') as 'kubo' | 'psa';
export const BYO_PROVIDER_NAME = process.env.BYO_IPFS_PROVIDER_NAME ?? 'external';

export interface PoolClient extends TestAccount {
  id: number;
  metrics: MetricsCollector;
}

export interface ClientPoolOptions {
  clientCount: number;
  label: string;
}

/** Options for creating a pool of BYO-mode clients */
export interface ByoPoolOptions extends ClientPoolOptions {
  /** External provider config -- all BYO clients share this provider */
  externalProvider: ExternalProviderConfig;
  /** Pinning mode for BYO clients */
  pinningMode: 'external' | 'dual';
}

/** A pool client augmented with BYO provider and mode */
export interface ByoPoolClient extends PoolClient {
  provider: PinningProvider;
  pinningMode: PinningMode;
  externalProvider: ExternalProviderConfig;
}

/**
 * Create a pool of N authenticated CipherBoxClient instances.
 *
 * Each client has its own test account, vault, metrics collector, and
 * instance-scoped axios (no shared singleton).
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
    // Zero harness-owned key material (client.destroy() only clears its internal copies)
    pc.privateKey.fill(0);
    pc.rootFolderKey.fill(0);
    pc.rootIpnsKeypair.privateKey.fill(0);
    await deleteTestAccount(pc, API_URL);
  }
}

/**
 * Create a pool of N BYO-mode authenticated CipherBoxClient instances.
 *
 * Each client has its own test account plus a PinningProvider instance
 * (KuboProvider or PsaProvider) for external pinning.
 *
 * Returns an empty array (with warning) if BYO_IPFS_ENDPOINT is not set,
 * allowing scenarios to skip gracefully.
 */
export async function createByoClientPool(opts: ByoPoolOptions): Promise<ByoPoolClient[]> {
  if (!BYO_ENDPOINT) {
    console.warn(
      'BYO_IPFS_ENDPOINT not set -- skipping BYO pool creation. ' +
        'Set BYO_IPFS_ENDPOINT, BYO_IPFS_AUTH_TOKEN, and optionally BYO_IPFS_PROTOCOL to run BYO scenarios.'
    );
    return [];
  }

  const basePool = await createClientPool({
    clientCount: opts.clientCount,
    label: opts.label,
  });

  const byoPool: ByoPoolClient[] = basePool.map((pc) => {
    const provider: PinningProvider =
      opts.externalProvider.protocol === 'psa'
        ? new PsaProvider(opts.externalProvider.endpoint, opts.externalProvider.authToken)
        : new KuboProvider(opts.externalProvider.endpoint, opts.externalProvider.authToken);

    return {
      ...pc,
      provider,
      pinningMode: opts.pinningMode,
      externalProvider: opts.externalProvider,
    };
  });

  console.log(
    `BYO pool: ${byoPool.length} clients with ${opts.externalProvider.protocol} provider ` +
      `(mode: ${opts.pinningMode}, endpoint: ${opts.externalProvider.endpoint})`
  );

  return byoPool;
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
  } catch (err) {
    console.warn(`Failed to write metrics report: ${(err as Error).message}`);
  }

  return metrics;
}
