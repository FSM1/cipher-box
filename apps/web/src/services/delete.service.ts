import { unpinFromIpfs } from '../lib/api/ipfs';
import { useQuotaStore } from '../stores/quota.store';

/**
 * Deletes a file by unpinning from IPFS and updating quota.
 *
 * In v2 metadata, the caller must first resolve the file's per-IPNS metadata
 * to obtain the CID before calling this function. The folder metadata only
 * contains a FilePointer with fileMetaIpnsName, not the CID directly.
 *
 * @param cid - CID of the file to delete
 * @param sizeBytes - Size of the file (for quota update)
 */
export async function deleteFile(cid: string, sizeBytes: number): Promise<void> {
  // 1. Unpin from IPFS via backend
  await unpinFromIpfs(cid);

  // 2. Update local quota
  const quotaStore = useQuotaStore.getState();
  quotaStore.removeUsage(sizeBytes);

  // TODO: Phase 14 should add TEE unenrollment for orphaned file IPNS records.
  // Currently, the file IPNS record and its TEE enrollment are left to expire
  // naturally (24h IPNS record lifetime, TEE republishing will stop after
  // the enrollment entry is cleaned up). This is acceptable for v1 because:
  // - No data leakage (the encrypted metadata CID becomes unreachable)
  // - Storage cost is minimal (IPNS records are small)
  // - The republish service has capacity warnings at 1000+ records
}

/**
 * Deletes multiple files by unpinning from IPFS.
 *
 * @param files - Array of { cid, size } objects
 */
export async function deleteFiles(
  files: Array<{ cid: string; size: number }>
): Promise<{ succeeded: string[]; failed: string[] }> {
  const succeeded: string[] = [];
  const failed: string[] = [];

  for (const file of files) {
    try {
      await deleteFile(file.cid, file.size);
      succeeded.push(file.cid);
    } catch (error) {
      console.error(`Failed to delete ${file.cid}:`, error);
      failed.push(file.cid);
    }
  }

  return { succeeded, failed };
}
