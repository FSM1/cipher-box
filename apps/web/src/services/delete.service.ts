import { getSdkClient } from '../lib/sdk-provider';
import { useQuotaStore } from '../stores/quota.store';
import { logger } from '../lib/logger';

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
  // 1. Unpin from IPFS via the SDK's IPFS-transport facade (D-07)
  await getSdkClient().unpin(cid);

  // 2. Update local quota
  const quotaStore = useQuotaStore.getState();
  quotaStore.removeUsage(sizeBytes);
  // Fire-and-forget: fetchQuota swallows its own errors and reports failure via
  // the resolved flag, so branch on that to emit the reconcile warning (Phase 42-02).
  void quotaStore.fetchQuota().then((ok) => {
    if (!ok) logger.warn('quota reconcile failed');
  });

  // TEE unenrollment is handled by SDK's fireAndForgetUnenroll() on delete.
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
      logger.error(`Failed to delete ${file.cid}:`, error);
      failed.push(file.cid);
    }
  }

  return { succeeded, failed };
}
