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
  if (minSize < 0 || maxSize < minSize) {
    throw new Error(`Invalid size bounds: minSize=${minSize}, maxSize=${maxSize}`);
  }
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
        await metrics.measure(
          'downloadFile',
          async () => {
            if (!fileIpnsName) {
              throw new Error(
                `[Client ${pc.id}] File "${fileName}" not found in folder state after upload`
              );
            }
            const downloaded = await client.downloadFromIpns(fileIpnsName, rootFolderKey);
            if (downloaded.length !== data.length) {
              throw new Error(
                `[Client ${pc.id}] Size mismatch: uploaded ${data.length}, downloaded ${downloaded.length}`
              );
            }
            // Byte-level content verification
            if (Buffer.compare(Buffer.from(data), Buffer.from(downloaded)) !== 0) {
              throw new Error(
                `[Client ${pc.id}] Content mismatch for "${fileName}" (same size, different bytes)`
              );
            }
            return downloaded;
          },
          size
        );
      }
    } catch (err) {
      console.warn(
        `[Client ${pc.id}] File upload ${fileName} failed: ${(err as Error).message?.slice(0, 150)}`
      );
    }
  }
}
