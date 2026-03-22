/**
 * Mixed Workload Scenario
 *
 * Simulates realistic usage: folder CRUD, file uploads, renames, moves, deletes
 * with weighted probabilities. Tests the system under representative load.
 */

import { describe, it, afterAll } from 'vitest';
import {
  createClientPool,
  destroyClientPool,
  aggregateAndReport,
  type PoolClient,
} from '../harness/client-pool';
import { runMixedWorkload } from '../workloads/mixed-workload';

const NUM_CLIENTS = parseInt(process.env.LOAD_TEST_CLIENTS ?? '5', 10);
const OPS_PER_CLIENT = 45;

describe('Mixed Workload', () => {
  let pool: PoolClient[] = [];

  afterAll(async () => {
    await destroyClientPool(pool);
  });

  it(`${NUM_CLIENTS} clients × ${OPS_PER_CLIENT} mixed ops`, async () => {
    pool = await createClientPool({
      clientCount: NUM_CLIENTS,
      label: 'mixed',
    });

    const results = await Promise.allSettled(
      pool.map((pc) => {
        pc.metrics.start();
        return runMixedWorkload(pc, {
          totalOps: OPS_PER_CLIENT,
          weights: {
            createFolder: 2,
            uploadFile: 4,
            renameItem: 1,
            moveItem: 1,
            deleteItem: 1,
          },
        }).finally(() => pc.metrics.stop());
      })
    );

    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    console.log(`\nClients completed: ${succeeded}/${pool.length}`);

    aggregateAndReport('Mixed Workload', pool);
  });
});
