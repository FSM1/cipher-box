/**
 * Folder CRUD Workload
 *
 * Creates, renames, moves, and deletes folders.
 */

import type { PoolClient } from '../harness/client-pool';

export interface FolderWorkloadOptions {
  /** Number of folder create-rename-delete cycles */
  cycles: number;
}

/**
 * Run a folder CRUD workload on a single client.
 * Individual operation failures are recorded as errors but don't abort the workload.
 */
export async function runFolderWorkload(
  pc: PoolClient,
  opts: FolderWorkloadOptions
): Promise<void> {
  const { client, rootIpnsName, metrics } = pc;

  for (let i = 0; i < opts.cycles; i++) {
    const name = `load-folder-${pc.id}-${i}`;

    try {
      // Create
      const folder = await metrics.measure('createFolder', () =>
        client.createFolder(rootIpnsName, name)
      );

      // Rename
      try {
        await metrics.measure('renameItem', () =>
          client.renameItem(rootIpnsName, folder.id, `${name}-renamed`)
        );
      } catch {
        /* non-fatal — continue to delete */
      }

      // Delete
      try {
        await metrics.measure('deleteItem', () => client.deleteItem(rootIpnsName, folder.id));
      } catch {
        /* non-fatal */
      }
    } catch {
      /* create failed — skip rename and delete for this cycle */
    }
  }
}
