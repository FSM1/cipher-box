import { useCallback } from 'react';
import { uploadFiles, UploadedFile } from '../services/upload.service';
import { useUploadStore } from '../stores/upload.store';
import { useQuotaStore } from '../stores/quota.store';
import { useAuthStore } from '../stores/auth.store';

/**
 * React hook for file upload with encryption, progress tracking, and quota management.
 *
 * Derives batch-level fields from the per-file upload Map for backward compatibility.
 * The SDK client is used for post-upload operations (adding files to folders) via useFileOperations.
 */
export function useFileUpload() {
  const files = useUploadStore((s) => s.files);
  const reset = useUploadStore((s) => s.reset);

  const { usedBytes, limitBytes, remainingBytes, canUpload, fetchQuota } = useQuotaStore();
  const { vaultKeypair } = useAuthStore();

  // Derive batch-level status from per-file Map
  const fileEntries = Array.from(files.values());
  const hasActiveUpload = fileEntries.some(
    (f) => f.status === 'encrypting' || f.status === 'uploading'
  );
  const hasError = fileEntries.some((f) => f.status === 'error');
  const activeFile = fileEntries.find((f) => f.status === 'encrypting' || f.status === 'uploading');

  const upload = useCallback(
    async (filesToUpload: File[]): Promise<UploadedFile[]> => {
      if (!vaultKeypair) {
        throw new Error('No keypair available - please log in again');
      }

      // Refresh quota before upload
      await fetchQuota();

      return uploadFiles(filesToUpload, vaultKeypair.publicKey);
    },
    [vaultKeypair, fetchQuota]
  );

  return {
    // State (derived from per-file Map)
    status: hasError
      ? ('error' as const)
      : hasActiveUpload
        ? ('uploading' as const)
        : ('idle' as const),
    progress: activeFile?.progress ?? 0,
    currentFile: activeFile?.filename ?? null,
    totalFiles: fileEntries.length,
    completedFiles: fileEntries.filter((f) => f.status === 'complete').length,
    error: fileEntries.find((f) => f.error)?.error ?? null,
    isUploading: hasActiveUpload,

    // Quota
    usedBytes,
    limitBytes,
    remainingBytes,
    canUpload,

    // Actions
    upload,
    cancel: () => {
      // Cancel all active uploads
      for (const f of files.values()) {
        if (f.status === 'encrypting' || f.status === 'uploading') {
          useUploadStore.getState().cancelFile(f.id);
        }
      }
    },
    reset,
  };
}
