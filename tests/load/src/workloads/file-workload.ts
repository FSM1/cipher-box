/**
 * File Upload/Download Workload
 *
 * Parameterized workload that uploads and downloads files of varying sizes.
 */

import type { PoolClient } from '../harness/client-pool';

export interface FileWorkloadOptions {
  /** Number of files to upload */
  fileCount: number;
  /** Min file size in bytes */
  minSize: number;
  /** Max file size in bytes */
  maxSize: number;
  /** Whether to verify downloads after upload */
  verifyDownloads: boolean;
}

/**
 * Run a file upload workload on a single client.
 */
export async function runFileWorkload(pc: PoolClient, opts: FileWorkloadOptions): Promise<void> {
  const { fileCount, minSize, maxSize, verifyDownloads } = opts;
  const { client, rootIpnsName, rootFolderKey, metrics } = pc;

  for (let i = 0; i < fileCount; i++) {
    const size = minSize + Math.floor(Math.random() * (maxSize - minSize));
    const data = new Uint8Array(size);
    crypto.getRandomValues(data);
    const fileName = `load-${pc.id}-file-${i}-${size}b.bin`;

    // Upload
    await metrics.measure(
      'uploadFile',
      () => client.uploadFile(rootIpnsName, data, fileName, 'application/octet-stream'),
      size
    );

    // Optionally download and verify
    if (verifyDownloads) {
      const folder = (client as any).folderTree.get(rootIpnsName);
      const child = folder?.children.find((c: any) => c.name === fileName);
      if (child?.fileMetaIpnsName) {
        const downloaded = await metrics.measure(
          'downloadFile',
          () => client.downloadFromIpns(child.fileMetaIpnsName, rootFolderKey),
          size
        );
        if (downloaded.length !== data.length) {
          throw new Error(
            `Size mismatch: uploaded ${data.length}, downloaded ${downloaded.length}`
          );
        }
      }
    }
  }
}
