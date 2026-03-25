/**
 * BYO Capacity Ceiling Scenario
 *
 * Stepped concurrency increase to find the BYO capacity ceiling on
 * the CipherBox API. Each step creates N BYO clients, runs a short
 * workload, and reports per-operation metrics.
 *
 * The escalating concurrency reveals where the API starts to degrade:
 * - Rising p95 latency on register-cid or ipns-publish
 * - Error rate increasing (429s, 5xx responses)
 * - Throughput plateau
 *
 * The external provider (Pinata, Kubo, etc.) may also rate-limit at
 * higher concurrency. byo-pin latency spikes indicate provider limits,
 * while register-cid and ipns-publish metrics show CipherBox API capacity
 * uncontaminated by provider latency.
 *
 * Environment variables:
 *   BYO_IPFS_ENDPOINT      - External provider endpoint (required)
 *   BYO_IPFS_AUTH_TOKEN     - Auth token for external provider
 *   BYO_IPFS_PROTOCOL       - 'kubo' (default) or 'psa'
 *   BYO_IPFS_PROVIDER_NAME  - Provider label for reports
 */

import { describe, it } from 'vitest';
import {
  createByoClientPool,
  destroyClientPool,
  aggregateAndReport,
  BYO_ENDPOINT,
  BYO_AUTH_TOKEN,
  BYO_PROTOCOL,
  BYO_PROVIDER_NAME,
} from '../harness/client-pool';
import { runByoFileWorkload } from '../workloads/byo-file-workload';

const STEPS = [50, 100, 200, 500, 1000];
const FILES_PER_CLIENT = 5; // Fewer files per step to keep runtime reasonable

describe('BYO Capacity Ceiling', () => {
  for (const clientCount of STEPS) {
    it(
      `${clientCount} BYO clients x ${FILES_PER_CLIENT} files`,
      async () => {
        const pool = await createByoClientPool({
          clientCount,
          label: `byo-ceiling-${clientCount}`,
          externalProvider: {
            endpoint: BYO_ENDPOINT ?? '',
            authToken: BYO_AUTH_TOKEN,
            protocol: BYO_PROTOCOL,
            providerName: BYO_PROVIDER_NAME,
          },
          pinningMode: 'external',
        });

        if (pool.length === 0) {
          console.warn('BYO_IPFS_ENDPOINT not set -- skipping capacity ceiling test');
          return;
        }

        const results = await Promise.allSettled(
          pool.map((pc) => {
            pc.metrics.start();
            return runByoFileWorkload(pc, {
              fileCount: FILES_PER_CLIENT,
              minSize: 1_024,
              maxSize: 100 * 1_024,
              verifyDownloads: false,
            }).finally(() => pc.metrics.stop());
          })
        );

        const succeeded = results.filter((r) => r.status === 'fulfilled').length;
        const failed = results.filter((r) => r.status === 'rejected').length;
        console.log(
          `\n[${clientCount} clients] Completed: ${succeeded} succeeded, ${failed} failed`
        );

        await aggregateAndReport(`BYO Ceiling (${clientCount})`, pool);
        await destroyClientPool(pool);
      },
      { timeout: 600_000 }
    );
  }
});
