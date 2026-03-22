/**
 * File Upload/Download Workload
 *
 * Parameterized workload that uploads and downloads files of varying sizes.
 * Individual operation failures are recorded as errors but don't abort the workload.
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
    // crypto.getRandomValues() has a 65536 byte limit per call
    for (let offset = 0; offset < size; offset += 65536) {
      const chunk = new Uint8Array(data.buffer, offset, Math.min(65536, size - offset));
      crypto.getRandomValues(chunk);
    }
    const fileName = `load-${pc.id}-file-${i}-${size}b.bin`;

    try {
      // Upload
      await metrics.measure(
        'uploadFile',
        () => client.uploadFile(rootIpnsName, data, fileName, 'application/octet-stream'),
        size
      );

      // Optionally download and verify
      if (verifyDownloads) {
        const folder = client.getFolderTree().get(rootIpnsName);
        const child = folder?.children.find((c) => c.name === fileName);
        const fileIpnsName =
          child && 'fileMetaIpnsName' in child ? child.fileMetaIpnsName : undefined;
        if (fileIpnsName) {
          const downloaded = await metrics.measure(
            'downloadFile',
            () => client.downloadFromIpns(fileIpnsName, rootFolderKey),
            size
          );
          if (downloaded.length !== data.length) {
            console.warn(
              `[Client ${pc.id}] Size mismatch: uploaded ${data.length}, downloaded ${downloaded.length}`
            );
          }
        }
      }
    } catch (err) {
      console.warn(
        `[Client ${pc.id}] File upload ${fileName} failed: ${(err as Error).message?.slice(0, 150)}`
      );
    }
  }
}
