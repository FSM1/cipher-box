/**
 * BYO File Upload/Download Workload
 *
 * Exercises the full BYO upload path: pin to external provider, register CID
 * with CipherBox API, publish IPNS records. Records per-operation metrics
 * with byo- prefix to distinguish from CipherBox-only metrics.
 *
 * Supports two modes:
 * - Kubo: direct upload to external node via KuboProvider.pin()
 * - PSA: transient relay upload (CipherBox upload -> PSA pinByCid -> CipherBox unpin)
 */

import type { ByoPoolClient } from '../harness/client-pool';
import { createSdkContext } from '../harness/client-pool';
import { PsaProvider, createAndPublishIpnsRecord } from '@cipherbox/sdk-core';

export interface ByoFileWorkloadOptions {
  /** Number of files to upload */
  fileCount: number;
  /** Min file size in bytes */
  minSize: number;
  /** Max file size in bytes */
  maxSize: number;
  /** Whether to verify downloads after upload (Kubo only; PSA does not support get) */
  verifyDownloads: boolean;
}

/**
 * Run a BYO file upload workload on a single client.
 *
 * Per-file operation sequence (Kubo mode):
 *   1. Generate random data (simulates encrypted content)
 *   2. Pin to external provider (byo-pin)
 *   3. Register CID with CipherBox API (register-cid)
 *   4. Publish IPNS record via CipherBox API (ipns-publish)
 *   5. Optional: verify download (byo-download)
 *   6. Cleanup: unpin from external provider (byo-unpin)
 *
 * Per-file operation sequence (PSA mode):
 *   1. Generate random data
 *   2. Upload to CipherBox relay (psa-relay-upload)
 *   3. Pin by CID on PSA service (psa-pin-by-cid)
 *   4. Unpin from CipherBox relay (psa-relay-unpin)
 *   5. Register CID with CipherBox API (register-cid)
 *   6. Publish IPNS record via CipherBox API (ipns-publish)
 *   7. Cleanup: unpin from PSA (byo-unpin)
 */
export async function runByoFileWorkload(
  pc: ByoPoolClient,
  opts: ByoFileWorkloadOptions
): Promise<void> {
  const { fileCount, minSize, maxSize, verifyDownloads } = opts;
  if (minSize < 0 || maxSize < minSize) {
    throw new Error(`Invalid size bounds: minSize=${minSize}, maxSize=${maxSize}`);
  }

  const isPsa = pc.provider instanceof PsaProvider;
  const { client, rootIpnsName, metrics } = pc;
  const sdkCtx = createSdkContext(pc);

  for (let i = 0; i < fileCount; i++) {
    const size = minSize + Math.floor(Math.random() * (maxSize - minSize + 1));
    const data = new Uint8Array(size);
    // crypto.getRandomValues() has a 65536 byte limit per call
    for (let offset = 0; offset < size; offset += 65536) {
      const chunk = new Uint8Array(data.buffer, offset, Math.min(65536, size - offset));
      crypto.getRandomValues(chunk);
    }

    let cid: string | undefined;
    let pinSize: number | undefined;
    try {
      if (isPsa) {
        // PSA transient relay flow
        // Step 1: Upload to CipherBox to make content available on IPFS network
        const relayResult = await metrics.measure(
          'psa-relay-upload',
          async () => {
            const axiosInstance = client.getContext().axiosInstance!;
            const blob = new Blob([data as BlobPart]);
            const formData = new FormData();
            formData.append('file', blob);
            const res = await axiosInstance.post<{ cid: string; size: number }>(
              '/ipfs/upload',
              formData
            );
            return res.data;
          },
          size
        );

        cid = relayResult.cid;
        pinSize = relayResult.size;

        // Step 2: Pin by CID on PSA service
        await metrics.measure('psa-pin-by-cid', async () => {
          await (pc.provider as PsaProvider).pinByCid(cid!, `load-${pc.id}-file-${i}`);
        });

        // Step 3: Unpin from CipherBox relay (content now on PSA service)
        await metrics.measure('psa-relay-unpin', async () => {
          const axiosInstance = client.getContext().axiosInstance!;
          await axiosInstance.post('/ipfs/unpin', { cid });
        });
      } else {
        // Kubo direct upload flow
        const pinResult = await metrics.measure(
          'byo-pin',
          () => pc.provider.pin(data, `load-${pc.id}-file-${i}`),
          size
        );
        cid = pinResult.cid;
        pinSize = pinResult.size;
      }

      // Register CID with CipherBox API (both modes)
      // BYO mode is enabled in createByoClientPool, so 403 is unexpected.
      try {
        await metrics.measure('register-cid', async () => {
          const axiosInstance = client.getContext().axiosInstance!;
          await axiosInstance.post('/ipfs/register-cid', { cid, sizeBytes: pinSize });
        });
      } catch (err) {
        const status = (err as { response?: { status?: number } }).response?.status;
        console.warn(
          `[Client ${pc.id}] register-cid failed (HTTP ${status ?? 'unknown'}): ${(err as Error).message?.slice(0, 100)}`
        );
      }

      // Publish IPNS record via CipherBox API (includes local record creation + signing + HTTP publish)
      await metrics.measure('ipns-publish', async () => {
        await createAndPublishIpnsRecord({
          ipnsPrivateKey: pc.rootIpnsKeypair.privateKey,
          ipnsName: rootIpnsName,
          metadataCid: cid!,
          sequenceNumber: BigInt(i),
          ctx: sdkCtx,
        });
      });

      // Optional: verify download (Kubo only -- PSA does not support content retrieval)
      if (verifyDownloads && !isPsa) {
        await metrics.measure(
          'byo-download',
          async () => {
            const downloaded = await pc.provider.get(cid!);
            if (downloaded.length !== data.length) {
              throw new Error(
                `[Client ${pc.id}] Size mismatch: uploaded ${data.length}, downloaded ${downloaded.length}`
              );
            }
            return downloaded;
          },
          size
        );
      }
    } catch (err) {
      console.warn(
        `[Client ${pc.id}] BYO file ${i} failed: ${(err as Error).message?.slice(0, 150)}`
      );
    } finally {
      // Cleanup: unpin from external provider whenever we have a CID
      // Runs even if later steps (ipns-publish, verify) threw
      if (cid) {
        try {
          await metrics.measure('byo-unpin', () => pc.provider.unpin(cid!));
        } catch (cleanupErr) {
          console.warn(
            `[Client ${pc.id}] Cleanup failed for file ${i}: ${(cleanupErr as Error).message?.slice(0, 150)}`
          );
        }
      }
    }
  }
}
