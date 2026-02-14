import { unpinFromIpfs } from '../lib/api/ipfs';
import { useQuotaStore } from '../stores/quota.store';

/**
 * Deletes a file by unpinning from IPFS and updating quota.
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
