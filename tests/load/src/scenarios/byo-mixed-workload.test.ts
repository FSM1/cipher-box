/**
 * Mixed CipherBox + BYO Workload Scenario
 *
 * The key scenario for answering: "How does adding BYO users affect
 * existing CipherBox-only users?"
 *
 * Runs CB-only and BYO clients concurrently, then reports metrics
 * per segment separately. The questions answered:
 *
 * 1. CB-only segment p95 vs 19.2 baseline p95: Do BYO users' lightweight
 *    API calls (register-cid, IPNS publish) degrade CipherBox-only UX?
 *
 * 2. BYO segment register-cid + ipns-publish latency: Does contention from
 *    CB-only heavy uploads slow down BYO API calls?
 *
 * 3. Error rates per segment: Which user type hits errors first under mixed load?
 *
 * Environment variables for ratio sweeps:
 *   LOAD_TEST_CB_CLIENTS=50  LOAD_TEST_BYO_CLIENTS=200  (default)
 *   LOAD_TEST_CB_CLIENTS=100 LOAD_TEST_BYO_CLIENTS=500  (high load)
 *   LOAD_TEST_CB_CLIENTS=200 LOAD_TEST_BYO_CLIENTS=0    (CB-only baseline for comparison)
 *
 * BYO env vars:
 *   BYO_IPFS_ENDPOINT      - External provider endpoint (required for BYO segment)
 *   BYO_IPFS_AUTH_TOKEN     - Auth token for external provider
 *   BYO_IPFS_PROTOCOL       - 'kubo' (default) or 'psa'
 *   BYO_IPFS_PROVIDER_NAME  - Provider label for reports
 */

import { describe, it, afterAll } from 'vitest';
import {
  createClientPool,
  createByoClientPool,
  destroyClientPool,
  aggregateAndReport,
  BYO_ENDPOINT,
  BYO_AUTH_TOKEN,
  BYO_PROTOCOL,
  BYO_PROVIDER_NAME,
  type PoolClient,
  type ByoPoolClient,
} from '../harness/client-pool';
import { runFileWorkload } from '../workloads/file-workload';
import { runByoFileWorkload } from '../workloads/byo-file-workload';

const CB_CLIENTS = parseInt(process.env.LOAD_TEST_CB_CLIENTS ?? '50', 10);
const BYO_CLIENTS = parseInt(process.env.LOAD_TEST_BYO_CLIENTS ?? '200', 10);
const FILES_PER_CLIENT = 10;

describe('Mixed CipherBox + BYO Workload', () => {
  let cbPool: PoolClient[] = [];
  let byoPool: ByoPoolClient[] = [];

  afterAll(async () => {
    await destroyClientPool([...cbPool, ...byoPool]);
  });

  it(
    `${CB_CLIENTS} CB-only + ${BYO_CLIENTS} BYO clients x ${FILES_PER_CLIENT} files`,
    async () => {
      // Create both pools in parallel
      const [cbResult, byoResult] = await Promise.allSettled([
        createClientPool({ clientCount: CB_CLIENTS, label: 'mixed-cb' }),
        BYO_CLIENTS > 0
          ? createByoClientPool({
              clientCount: BYO_CLIENTS,
              label: 'mixed-byo',
              externalProvider: {
                endpoint: BYO_ENDPOINT ?? '',
                authToken: BYO_AUTH_TOKEN,
                protocol: BYO_PROTOCOL,
                providerName: BYO_PROVIDER_NAME,
              },
              pinningMode: 'external',
            })
          : Promise.resolve([]),
      ]);

      if (cbResult.status === 'rejected') throw cbResult.reason;
      cbPool = cbResult.value;

      if (byoResult.status === 'rejected') {
        console.warn(`BYO pool creation failed: ${byoResult.reason}`);
        byoPool = [];
      } else if (byoResult.value.length === 0 && BYO_CLIENTS > 0) {
        console.warn(
          'BYO pool empty (BYO_IPFS_ENDPOINT not set?) -- running CB-only for comparison'
        );
        byoPool = [];
      } else {
        byoPool = byoResult.value as ByoPoolClient[];
      }

      console.log(
        `\nMixed workload: ${cbPool.length} CB-only + ${byoPool.length} BYO clients ` +
          `x ${FILES_PER_CLIENT} files each`
      );

      // Run both workloads concurrently
      const allResults = await Promise.allSettled([
        // CipherBox-only clients run standard file workload
        ...cbPool.map((pc) => {
          pc.metrics.start();
          return runFileWorkload(pc, {
            fileCount: FILES_PER_CLIENT,
            minSize: 1_024,
            maxSize: 500 * 1_024,
            verifyDownloads: false,
          }).finally(() => pc.metrics.stop());
        }),
        // BYO clients run BYO file workload
        ...byoPool.map((pc) => {
          pc.metrics.start();
          return runByoFileWorkload(pc, {
            fileCount: FILES_PER_CLIENT,
            minSize: 1_024,
            maxSize: 500 * 1_024,
            verifyDownloads: false,
          }).finally(() => pc.metrics.stop());
        }),
      ]);

      const cbResults = allResults.slice(0, cbPool.length);
      const byoResults = allResults.slice(cbPool.length);

      const cbSucceeded = cbResults.filter((r) => r.status === 'fulfilled').length;
      const cbFailed = cbResults.filter((r) => r.status === 'rejected').length;
      const byoSucceeded = byoResults.filter((r) => r.status === 'fulfilled').length;
      const byoFailed = byoResults.filter((r) => r.status === 'rejected').length;

      console.log(`\nCB-only segment: ${cbSucceeded} succeeded, ${cbFailed} failed`);
      console.log(`BYO segment: ${byoSucceeded} succeeded, ${byoFailed} failed`);

      // Report separately for CB-only and BYO to compare impact
      console.log('\n=== CipherBox-Only Clients ===');
      await aggregateAndReport('Mixed (CB-only segment)', cbPool);

      if (byoPool.length > 0) {
        console.log('\n=== BYO Clients ===');
        await aggregateAndReport('Mixed (BYO segment)', byoPool);
      }

      // Key comparison: CB-only p95 in mixed vs the 19.2 baseline CB-only p95
      // If CB-only p95 degrades significantly, BYO users are competing for
      // shared resources (DB connections, HTTP connections, IPNS publish queue)
    },
    { timeout: 600_000 }
  );
});
