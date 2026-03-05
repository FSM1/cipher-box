import { useCallback } from 'react';
import { useFileUpload } from './useFileUpload';
import { useFolder } from './useFolder';
import { unpinFromIpfs } from '../lib/api/ipfs';
import { useUploadStore } from '../stores/upload.store';
import type { PendingReplacement } from '../stores/upload.store';
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

      // Check for duplicates within batch (independent of folder cache)
      const batchNames = new Set<string>();
      for (const f of files) {
        if (batchNames.has(f.name)) {
          useUploadStore.getState().setError(`Duplicate file name in selection: ${f.name}`);
          return false;
        }
        batchNames.add(f.name);
      }

      // Identify which files already exist in the target folder
      const folder = useFolderStore.getState().folders[folderId];
      const existingByName = new Map<string, string>(); // name → fileId
      if (folder) {
        for (const child of folder.children) {
          if (child.type === 'file') {
            existingByName.set(child.name, child.id);
          }
        }
      }
      const newFiles = files.filter((f) => !existingByName.has(f.name));
      const duplicateFiles = files.filter((f) => existingByName.has(f.name));

      let uploadedFiles: UploadedFile[] | undefined;
      try {
        uploadedFiles = await upload(files);

        useUploadStore.getState().setRegistering();

        // Build file index for mimeType lookup
        const filesByName = new Map(files.map((f) => [f.name, f]));

        // Build uploaded file index by name for quick lookup
        const uploadedByName = new Map(uploadedFiles.map((u) => [u.originalName, u]));

        // Register only genuinely new files in the folder
        if (newFiles.length > 0) {
          const newUploaded = newFiles
            .map((f) => uploadedByName.get(f.name))
            .filter((u): u is UploadedFile => !!u);

          await addFiles(
            folderId,
            newUploaded.map((uploaded) => ({
              cid: uploaded.cid,
              wrappedKey: uploaded.wrappedKey,
              iv: uploaded.iv,
              originalName: uploaded.originalName,
              originalSize: uploaded.originalSize,
              mimeType: filesByName.get(uploaded.originalName)?.type || 'application/octet-stream',
              encryptionMode: uploaded.encryptionMode,
            }))
          );
        }

        // Surface duplicates as pending replacements for the UI to handle
        if (duplicateFiles.length > 0) {
          const replacements: PendingReplacement[] = duplicateFiles
            .map((f) => {
              const uploaded = uploadedByName.get(f.name);
              const existingFileId = existingByName.get(f.name);
              if (!uploaded || !existingFileId) return null;
              return {
                fileName: f.name,
                fileId: existingFileId,
                parentId: folderId,
                encryptedData: {
                  cid: uploaded.cid,
                  wrappedKey: uploaded.wrappedKey,
                  iv: uploaded.iv,
                  size: uploaded.originalSize,
                  encryptionMode: uploaded.encryptionMode,
                },
              };
            })
            .filter((r): r is PendingReplacement => r !== null);

          useUploadStore.getState().setPendingReplacements(replacements);
        }

        useUploadStore.getState().setSuccess();
        return true;
      } catch (err) {
        const message = (err as Error).message;
        if (message !== 'Upload cancelled by user') {
          useUploadStore.getState().setError(message);

          // Clean up orphaned IPFS pins if upload succeeded but registration failed
          if (uploadedFiles?.length) {
            for (const f of uploadedFiles) {
              void unpinFromIpfs(f.cid).catch(() => {});
            }
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
