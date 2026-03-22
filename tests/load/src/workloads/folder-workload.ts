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
 */
export async function runFolderWorkload(
  pc: PoolClient,
  opts: FolderWorkloadOptions
): Promise<void> {
  const { client, rootIpnsName, metrics } = pc;

  for (let i = 0; i < opts.cycles; i++) {
    const name = `load-folder-${pc.id}-${i}`;

    // Create
    const folder = await metrics.measure('createFolder', () =>
      client.createFolder(rootIpnsName, name)
    );

    // Rename
    await metrics.measure('renameItem', () =>
      client.renameItem(rootIpnsName, folder.id, `${name}-renamed`)
    );

    // Delete
    await metrics.measure('deleteItem', () => client.deleteItem(rootIpnsName, folder.id));
  }
}
