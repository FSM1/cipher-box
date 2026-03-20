import { useCallback } from 'react';
import { uploadFiles, UploadedFile } from '../services/upload.service';
import { useUploadStore } from '../stores/upload.store';
import { useQuotaStore } from '../stores/quota.store';
import { useAuthStore } from '../stores/auth.store';
// Note: Upload uses upload.service.ts which has its own encryption, progress tracking,
// cancellation, and retry logic tightly coupled to useUploadStore. The SDK's uploadFile()
// combines encryption + upload + metadata in one call, which is a different flow.
// Full migration to SDK upload will happen when useFileOperations.addFile() is also migrated.

/**
 * React hook for file upload with encryption, progress tracking, and quota management.
 *
 * Currently uses upload.service.ts for the upload flow. The SDK client is used
 * for post-upload operations (adding files to folders) via useFileOperations.
 */
export function useFileUpload() {
  const { status, progress, currentFile, totalFiles, completedFiles, error, cancel, reset } =
    useUploadStore();

  const { usedBytes, limitBytes, remainingBytes, canUpload, fetchQuota } = useQuotaStore();
  const { vaultKeypair } = useAuthStore();

  const upload = useCallback(
    async (files: File[]): Promise<UploadedFile[]> => {
      if (!vaultKeypair) {
        throw new Error('No keypair available - please log in again');
      }

      // Refresh quota before upload
      await fetchQuota();

      return uploadFiles(files, vaultKeypair.publicKey);
    },
    [vaultKeypair, fetchQuota]
  );

  return {
    // State
    status,
    progress,
    currentFile,
    totalFiles,
    completedFiles,
    error,
    isUploading: status === 'encrypting' || status === 'uploading' || status === 'registering',

    // Quota
    usedBytes,
    limitBytes,
    remainingBytes,
    canUpload,

    // Actions
    upload,
    cancel,
    reset,
  };
}
