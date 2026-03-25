/**
 * SDK-Core Headless Workloads
 *
 * Direct sdk-core function calls without CipherBoxClient overhead.
 * Used for bottleneck isolation in load test scenarios.
 */

import * as sdkCore from '@cipherbox/sdk-core';
import type { SdkContext } from '@cipherbox/sdk-core';
import type { PoolClient } from '../harness/client-pool';
import { createSdkContext } from '../harness/client-pool';

export interface SdkWorkloadClient {
  pc: PoolClient;
  ctx: SdkContext;
}

/** Prepare a PoolClient for headless sdk-core workloads. */
export function prepareSdkClient(pc: PoolClient): SdkWorkloadClient {
  return { pc, ctx: createSdkContext(pc) };
}

/**
 * IPNS publish + resolve cycle workload.
 *
 * Each cycle publishes a new IPNS record then resolves it.
 * Sequence numbers start at 100 to avoid conflicting with real vault state.
 */
export async function runIpnsPublishWorkload(
  swc: SdkWorkloadClient,
  opts: { cycles: number }
): Promise<void> {
  const { pc, ctx } = swc;
  for (let i = 0; i < opts.cycles; i++) {
    // Publish
    try {
      await pc.metrics.measure('sdkIpnsPublish', () =>
        sdkCore.createAndPublishIpnsRecord({
          ipnsPrivateKey: pc.rootIpnsKeypair.privateKey,
          ipnsName: pc.rootIpnsName,
          metadataCid: `bafybeig${Date.now().toString(36)}${i.toString(36)}`,
          sequenceNumber: BigInt(i + 100),
          ctx,
        })
      );
    } catch (err) {
      console.warn(
        `[Client ${pc.id}] IPNS publish ${i} failed: ${(err as Error).message?.slice(0, 150)}`
      );
    }

    // Resolve
    try {
      await pc.metrics.measure('sdkIpnsResolve', () =>
        sdkCore.resolveIpnsRecord(pc.rootIpnsName, ctx)
      );
    } catch (err) {
      console.warn(
        `[Client ${pc.id}] IPNS resolve ${i} failed: ${(err as Error).message?.slice(0, 150)}`
      );
    }
  }
}

/**
 * Upload pipeline workload (encrypt + pin + file metadata IPNS publish).
 *
 * Calls sdkCore.uploadFile directly, bypassing CipherBoxClient folder tree
 * management to isolate the upload pipeline performance.
 */
export async function runUploadPipelineWorkload(
  swc: SdkWorkloadClient,
  opts: { fileCount: number; fileSizeBytes: number }
): Promise<void> {
  const { pc, ctx } = swc;
  for (let i = 0; i < opts.fileCount; i++) {
    const data = new Uint8Array(opts.fileSizeBytes);
    crypto.getRandomValues(data);

    try {
      const result = await pc.metrics.measure(
        'sdkUploadFile',
        () =>
          sdkCore.uploadFile({
            ctx,
            folderKey: pc.rootFolderKey,
            userPublicKey: pc.publicKey,
            data,
            fileId: crypto.randomUUID(),
            mimeType: 'application/octet-stream',
          }),
        opts.fileSizeBytes
      );
      // Clear the returned file key (security hygiene)
      result.fileKey.fill(0);
    } catch (err) {
      console.warn(
        `[Client ${pc.id}] Upload ${i} failed: ${(err as Error).message?.slice(0, 150)}`
      );
    }
  }
}

/**
 * Folder metadata read workload (IPNS resolve + IPFS fetch + decrypt).
 *
 * Uses loadFolderMetadata which resolves IPNS, fetches the CID,
 * and decrypts the folder metadata -- the full read path.
 */
export async function runFolderReadWorkload(
  swc: SdkWorkloadClient,
  opts: { cycles: number }
): Promise<void> {
  const { pc, ctx } = swc;
  for (let i = 0; i < opts.cycles; i++) {
    try {
      await pc.metrics.measure('sdkFolderRead', () =>
        sdkCore.loadFolderMetadata({
          ipnsName: pc.rootIpnsName,
          folderKey: pc.rootFolderKey,
          ctx,
        })
      );
    } catch (err) {
      console.warn(
        `[Client ${pc.id}] Folder read ${i} failed: ${(err as Error).message?.slice(0, 150)}`
      );
    }
  }
}
