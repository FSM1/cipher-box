/**
 * Mixed Workload
 *
 * Simulates realistic usage: a mix of folder CRUD, file uploads,
 * renames, moves, and deletes with weighted probabilities.
 */

import type { PoolClient } from '../harness/client-pool';

export interface MixedWorkloadOptions {
  /** Total number of operations */
  totalOps: number;
  /** Operation weights (sum doesn't need to be 1, they're normalized) */
  weights?: {
    createFolder?: number;
    uploadFile?: number;
    renameItem?: number;
    moveItem?: number;
    deleteItem?: number;
  };
}

const DEFAULT_WEIGHTS = {
  createFolder: 2,
  uploadFile: 4,
  renameItem: 1,
  moveItem: 1,
  deleteItem: 1,
};

/**
 * Run a mixed workload on a single client.
 */
export async function runMixedWorkload(pc: PoolClient, opts: MixedWorkloadOptions): Promise<void> {
  const { client, rootIpnsName, metrics } = pc;
  const weights = { ...DEFAULT_WEIGHTS, ...opts.weights };
  const totalWeight = Object.values(weights).reduce((a, b) => a + b, 0);

  // Track created items for rename/move/delete targets
  const folderIds: Array<{
    id: string;
    ipnsName: string;
    folderKey: Uint8Array;
    ipnsPrivateKey: Uint8Array;
  }> = [];
  const fileIds: Array<{ id: string; name: string }> = [];

  for (let i = 0; i < opts.totalOps; i++) {
    const roll = Math.random() * totalWeight;
    let cumulative = 0;

    // Pick operation based on weighted random
    if ((cumulative += weights.createFolder) > roll) {
      // Create folder
      try {
        const name = `mix-folder-${pc.id}-${i}`;
        const folder = await metrics.measure('createFolder', () =>
          client.createFolder(rootIpnsName, name)
        );
        folderIds.push(folder);
      } catch {
        /* non-fatal */
      }
    } else if ((cumulative += weights.uploadFile) > roll) {
      // Upload file
      try {
        const size = 1024 + Math.floor(Math.random() * 50_000);
        const data = new Uint8Array(size);
        crypto.getRandomValues(data);
        const fileName = `mix-file-${pc.id}-${i}.bin`;

        await metrics.measure(
          'uploadFile',
          () => client.uploadFile(rootIpnsName, data, fileName, 'application/octet-stream'),
          size
        );

        const folder = client.getFolderTree().get(rootIpnsName);
        const child = folder?.children.find((c: any) => c.name === fileName);
        if (child) fileIds.push({ id: child.id, name: fileName });
      } catch {
        /* non-fatal */
      }
    } else if ((cumulative += weights.renameItem) > roll) {
      // Rename a random file
      if (fileIds.length > 0) {
        const idx = Math.floor(Math.random() * fileIds.length);
        const target = fileIds[idx];
        const newName = `${target.name}-r${i}`;
        try {
          await metrics.measure('renameItem', () =>
            client.renameItem(rootIpnsName, target.id, newName)
          );
          fileIds[idx] = { ...target, name: newName };
        } catch {
          /* non-fatal */
        }
      }
    } else if ((cumulative += weights.moveItem) > roll) {
      // Move a file into a folder (if both exist)
      if (fileIds.length > 0 && folderIds.length > 0) {
        const fileIdx = Math.floor(Math.random() * fileIds.length);
        const folderIdx = Math.floor(Math.random() * folderIds.length);
        const targetFolder = folderIds[folderIdx];

        // Ensure target folder is registered
        if (!client.hasFolder(targetFolder.ipnsName)) {
          client.registerFolder(
            targetFolder.ipnsName,
            targetFolder.folderKey,
            { publicKey: new Uint8Array(0), privateKey: targetFolder.ipnsPrivateKey },
            [],
            1n
          );
        }

        try {
          await metrics.measure('moveItem', () =>
            client.moveItem(rootIpnsName, targetFolder.ipnsName, fileIds[fileIdx].id)
          );
          fileIds.splice(fileIdx, 1); // Remove from root tracking
        } catch {
          /* non-fatal */
        }
      }
    } else {
      // Delete a random item
      if (fileIds.length > 0) {
        const idx = Math.floor(Math.random() * fileIds.length);
        try {
          await metrics.measure('deleteItem', () =>
            client.deleteItem(rootIpnsName, fileIds[idx].id)
          );
          fileIds.splice(idx, 1);
        } catch {
          /* non-fatal */
        }
      } else if (folderIds.length > 0) {
        const idx = Math.floor(Math.random() * folderIds.length);
        try {
          await metrics.measure('deleteItem', () =>
            client.deleteItem(rootIpnsName, folderIds[idx].id)
          );
          folderIds.splice(idx, 1);
        } catch {
          /* non-fatal */
        }
      }
    }
  }
}
