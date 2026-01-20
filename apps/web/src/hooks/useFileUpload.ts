import { useCallback } from 'react';
import { uploadFiles, UploadedFile } from '../services/upload.service';
import { useUploadStore } from '../stores/upload.store';
import { useQuotaStore } from '../stores/quota.store';
import { useAuthStore } from '../stores/auth.store';

/**
 * React hook for file upload with encryption, progress tracking, and quota management.
 *
 * @example
 * ```tsx
 * function UploadButton() {
 *   const {
 *     upload,
 *     cancel,
 *     reset,
 *     isUploading,
 *     progress,
 *     currentFile,
 *     error,
 *     canUpload,
 *   } = useFileUpload();
 *
 *   const handleFiles = async (files: File[]) => {
 *     const totalSize = files.reduce((s, f) => s + f.size, 0);
 *     if (!canUpload(totalSize)) {
 *       alert('Not enough space');
 *       return;
 *     }
 *     try {
 *       const results = await upload(files);
 *       console.log('Uploaded:', results);
 *     } catch (err) {
 *       // Error already in state via error
 *     }
 *   };
 *
 *   return (
 *     <div>
 *       {isUploading && <div>Uploading {currentFile}... {progress}%</div>}
 *       {error && <div>Error: {error}</div>}
 *       <button onClick={() => cancel()} disabled={!isUploading}>Cancel</button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useFileUpload() {
  const { status, progress, currentFile, totalFiles, completedFiles, error, cancel, reset } =
    useUploadStore();

  const { usedBytes, limitBytes, remainingBytes, canUpload, fetchQuota } = useQuotaStore();
  const { derivedKeypair } = useAuthStore();

  const upload = useCallback(
    async (files: File[]): Promise<UploadedFile[]> => {
      if (!derivedKeypair) {
        throw new Error('No keypair available - please log in again');
      }

      // Refresh quota before upload
      await fetchQuota();

      return uploadFiles(files, derivedKeypair.publicKey);
    },
    [derivedKeypair, fetchQuota]
  );

  return {
    // State
    status,
    progress,
    currentFile,
    totalFiles,
    completedFiles,
    error,
    isUploading: status === 'encrypting' || status === 'uploading',

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
