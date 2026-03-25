/**
 * BYO Upload Throughput Scenario
 *
 * N BYO clients each upload M files (1KB-500KB) via their external provider,
 * measuring per-operation latency: byo-pin, register-cid, ipns-publish.
 *
 * Compares against CipherBox-only upload-throughput baseline from Phase 19.2.
 * BYO users offload IPFS pinning to their own node, so the CipherBox API
 * only handles CID registration (~5ms) and IPNS publish (~50ms) per file.
 *
 * Environment variables:
 *   BYO_IPFS_ENDPOINT   - External provider endpoint (required)
 *   BYO_IPFS_AUTH_TOKEN  - Auth token for external provider
 *   BYO_IPFS_PROTOCOL   - 'kubo' (default) or 'psa'
 *   BYO_IPFS_PROVIDER_NAME - Provider label for reports
 *   LOAD_TEST_CLIENTS   - Number of BYO clients (default: 10)
 */

import { describe, it, afterAll } from 'vitest';
import {
  createByoClientPool,
  destroyClientPool,
  aggregateAndReport,
  BYO_ENDPOINT,
  BYO_AUTH_TOKEN,
  BYO_PROTOCOL,
  BYO_PROVIDER_NAME,
  type ByoPoolClient,
} from '../harness/client-pool';
import { runByoFileWorkload } from '../workloads/byo-file-workload';

const NUM_CLIENTS = parseInt(process.env.LOAD_TEST_CLIENTS ?? '10', 10);
const FILES_PER_CLIENT = 20;

describe('BYO Upload Throughput', () => {
  let pool: ByoPoolClient[] = [];

  afterAll(async () => {
    await destroyClientPool(pool);
  });

  it(
    `${NUM_CLIENTS} BYO clients x ${FILES_PER_CLIENT} files (1KB-500KB)`,
    async () => {
      pool = await createByoClientPool({
        clientCount: NUM_CLIENTS,
        label: 'byo-upload-throughput',
        externalProvider: {
          endpoint: BYO_ENDPOINT ?? '',
          authToken: BYO_AUTH_TOKEN,
          protocol: BYO_PROTOCOL,
          providerName: BYO_PROVIDER_NAME,
        },
        pinningMode: 'external',
      });

      if (pool.length === 0) {
        console.warn('BYO_IPFS_ENDPOINT not set -- skipping BYO throughput test');
        return;
      }

      const results = await Promise.allSettled(
        pool.map((pc) => {
          pc.metrics.start();
          return runByoFileWorkload(pc, {
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

      await aggregateAndReport('BYO Upload Throughput', pool);
    },
    { timeout: 300_000 }
  );
});
