import { useCallback } from 'react';
import { useFileUpload } from './useFileUpload';
import { useFolder } from './useFolder';
import { unpinFromIpfs } from '../lib/api/ipfs';
import { useUploadStore } from '../stores/upload.store';
import { useQuotaStore } from '../stores/quota.store';
import { useFolderStore } from '../stores/folder.store';
import type { UploadedFile } from '../services/upload.service';

export const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB per FILE-01

/**
 * Check whether a drag event carries external files from the OS (Finder/Explorer)
 * rather than an internal app drag (which sets application/json).
 */
export function isExternalFileDrag(dataTransfer: DataTransfer): boolean {
  return dataTransfer.types.includes('Files') && !dataTransfer.types.includes('application/json');
}

/**
 * Hook for handling external file drops (from Finder/Explorer) anywhere in the app.
 *
 * Provides a `handleFileDrop(files, folderId)` callback that validates,
 * encrypts, uploads, and registers files in the target folder.
 */
export function useDropUpload() {
  const { upload, canUpload, isUploading } = useFileUpload();
  const { addFiles } = useFolder();

  const handleFileDrop = useCallback(
    async (files: File[], folderId: string): Promise<boolean> => {
      // Filter out oversized files
      const oversized = files.filter((f) => f.size > MAX_FILE_SIZE);
      if (oversized.length > 0) {
        useUploadStore
          .getState()
          .setError(`Files exceed 100MB limit: ${oversized.map((f) => f.name).join(', ')}`);
        return false;
      }

      if (files.length === 0) return false;

      // Check quota
      const totalSize = files.reduce((sum, f) => sum + f.size, 0);
      if (!canUpload(totalSize)) {
        useUploadStore.getState().setError('Not enough storage space for these files');
        return false;
      }

      // Check for duplicate names in target folder
      const folder = useFolderStore.getState().folders[folderId];
      if (folder) {
        const existingNames = new Set(folder.children.map((c) => c.name));
        const duplicates = files.filter((f) => existingNames.has(f.name));
        if (duplicates.length > 0) {
          useUploadStore
            .getState()
            .setError(
              `File${duplicates.length > 1 ? 's' : ''} already exist${duplicates.length === 1 ? 's' : ''} in this folder: ${duplicates.map((f) => f.name).join(', ')}`
            );
          return false;
        }

        // Check for duplicates within batch
        const batchNames = new Set<string>();
        for (const f of files) {
          if (batchNames.has(f.name)) {
            useUploadStore.getState().setError(`Duplicate file name in selection: ${f.name}`);
            return false;
          }
          batchNames.add(f.name);
        }
      }

      let uploadedFiles: UploadedFile[] | undefined;
      try {
        uploadedFiles = await upload(files);

        useUploadStore.getState().setRegistering();

        await addFiles(
          folderId,
          uploadedFiles.map((uploaded) => ({
            cid: uploaded.cid,
            wrappedKey: uploaded.wrappedKey,
            iv: uploaded.iv,
            originalName: uploaded.originalName,
            originalSize: uploaded.originalSize,
          }))
        );

        useUploadStore.getState().setSuccess();
        return true;
      } catch (err) {
        const message = (err as Error).message;
        if (message !== 'Upload cancelled by user') {
          useUploadStore.getState().setError(message);

          // Clean up orphaned IPFS pins if upload succeeded but registration failed
          if (uploadedFiles?.length) {
            uploadedFiles.forEach((f) => unpinFromIpfs(f.cid).catch(() => {}));
            useQuotaStore.getState().fetchQuota();
          }
        }
        return false;
      }
    },
    [upload, canUpload, addFiles]
  );

  return { handleFileDrop, isUploading };
}
