import { useCallback } from 'react';
import { logger } from '../lib/logger';
import { useUploadStore, createUploadId } from '../stores/upload.store';
import { useQuotaStore } from '../stores/quota.store';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useAuthStore } from '../stores/auth.store';
import { getSdkClient, hasSdkClient } from '../lib/sdk-provider';
import { getRootFolderState } from './folder-helpers';
import { getEncryptionWorker } from '../services/encrypt-worker.service';
import type { PendingReplacement } from '../stores/upload.store';

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
 * Uses the SDK's uploadFiles() batch method for new files (single folder
 * publish for the entire batch) with Web Worker encryption.
 * Duplicate files use the old encrypt+upload path for the Replace dialog.
 * All IPNS state is managed by the SDK -- no dual-path conflicts.
 */
export function useDropUpload() {
  const isUploading = useUploadStore((s) => {
    for (const f of s.files.values()) {
      if (f.status === 'encrypting' || f.status === 'uploading') return true;
    }
    return false;
  });

  const handleFileDrop = useCallback(async (files: File[], folderId: string): Promise<boolean> => {
    // Filter out oversized files
    const oversized = files.filter((f) => f.size > MAX_FILE_SIZE);
    if (oversized.length > 0) {
      logger.error(`[Upload] Files exceed 100MB limit: ${oversized.map((f) => f.name).join(', ')}`);
      return false;
    }

    if (files.length === 0) return false;

    // Check quota
    const totalSize = files.reduce((sum, f) => sum + f.size, 0);
    const quotaStore = useQuotaStore.getState();
    if (!quotaStore.canUpload(totalSize)) {
      logger.error('[Upload] Not enough storage space for these files');
      return false;
    }

    // Check for duplicates within batch
    const batchNames = new Set<string>();
    for (const f of files) {
      if (batchNames.has(f.name)) {
        logger.error(`[Upload] Duplicate file name in selection: ${f.name}`);
        return false;
      }
      batchNames.add(f.name);
    }

    // Identify which files already exist in the target folder
    // TODO(phase 63): use Node.kind to distinguish file/folder; SealedChildRef has no .type or .id
    const folder = useFolderStore.getState().folders[folderId];
    const existingByName = new Map<string, string>(); // name -> fileId (phase 63: use Node id)
    const existingFolderNames = new Set<string>();
    if (folder) {
      for (const child of folder.children) {
        // Phase 63 placeholder: treat all children as potential name conflicts by name only
        existingByName.set(child.name, child.ipnsName);
        // existingFolderNames is populated by phase 63 via Node.kind discrimination
      }
    }

    // Fail fast on file-folder name collisions
    const folderNameConflicts = files.filter((f) => existingFolderNames.has(f.name));
    if (folderNameConflicts.length > 0) {
      logger.error(
        `[Upload] Cannot upload file(s) with the same name as an existing folder: ${folderNameConflicts.map((f) => f.name).join(', ')}`
      );
      return false;
    }

    const newFiles = files.filter((f) => !existingByName.has(f.name));
    const duplicateFiles = files.filter((f) => existingByName.has(f.name));

    if (!hasSdkClient()) {
      logger.error('[Upload] SDK not initialized -- please log in again');
      return false;
    }

    const client = getSdkClient();

    // Resolve parent folder
    const folders = useFolderStore.getState().folders;
    const vault = useVaultStore.getState();
    const parentFolder =
      folderId === 'root' ? getRootFolderState(vault, folders) : folders[folderId];
    if (!parentFolder) {
      logger.error('[Upload] Parent folder not found');
      return false;
    }

    const orphanCids: string[] = []; // Only unregistered CIDs (duplicates staged for replacement)
    let currentDupUploadId: string | undefined; // Tracks current duplicate file for error reporting

    try {
      // Upload new files via SDK batch pipeline (single folder publish for all)
      const uploadIdMap = new Map<string, string>(); // fileName -> uploadId
      if (newFiles.length > 0) {
        // Register all files in upload store first (for UI progress rows)
        for (const file of newFiles) {
          const uploadId = createUploadId(file.name);
          uploadIdMap.set(file.name, uploadId);
          useUploadStore.getState().addFile(uploadId, file.name, folderId, file);
        }

        try {
          // Read file data into Uint8Array (detect read errors early before entering SDK)
          const fileEntries: Array<{ data: Uint8Array; fileName: string; mimeType: string }> = [];
          for (const file of newFiles) {
            const uploadId = uploadIdMap.get(file.name)!;
            // Check if cancelled before reading
            if (!useUploadStore.getState().files.get(uploadId)) {
              continue; // User cancelled this file before it started
            }
            const data = new Uint8Array(await file.arrayBuffer());
            fileEntries.push({
              data,
              fileName: file.name,
              mimeType: file.type || 'application/octet-stream',
            });
          }

          if (fileEntries.length > 0) {
            // Get encryption Worker's encryptFn for off-main-thread encryption
            const encryptionWorker = getEncryptionWorker();
            const encryptFn = encryptionWorker.createEncryptFn();

            const result = await client.uploadFiles(
              parentFolder.ipnsName,
              fileEntries,
              {
                onFileProgress: (fileName, percent) => {
                  const uploadId = uploadIdMap.get(fileName);
                  if (uploadId) {
                    useUploadStore.getState().updateFileProgress(uploadId, percent);
                  }
                },
                onFileComplete: (fileName) => {
                  const uploadId = uploadIdMap.get(fileName);
                  if (uploadId) {
                    useUploadStore.getState().setFileStatus(uploadId, 'complete');
                  }
                },
                onFileError: (fileName, error) => {
                  const uploadId = uploadIdMap.get(fileName);
                  if (uploadId) {
                    useUploadStore.getState().setFileStatus(uploadId, 'error', error);
                  }
                },
              },
              { encryptFn }
            );

            // Failures already surfaced via onFileError callback (sets upload store to 'error').
            if (result.failures.length > 0) {
              logger.warn(
                `[Upload] Batch upload partial failure: ${result.failures.length} file(s) failed`,
                result.failures
              );
            }
          }
        } catch (batchErr) {
          // Mark all non-complete new-file rows as error so UI doesn't get stuck
          const msg = (batchErr as Error).message;
          for (const [, uploadId] of uploadIdMap) {
            const entry = useUploadStore.getState().files.get(uploadId);
            if (entry && entry.status !== 'complete') {
              useUploadStore.getState().setFileStatus(uploadId, 'error', msg);
            }
          }
          throw batchErr; // Re-throw so outer catch handles orphan cleanup
        }
      }

      // Handle duplicate files: encrypt + upload to IPFS, then surface as pending replacements
      // (These don't get registered in the folder -- the user decides via the Replace dialog)
      // Duplicate files always upload to CipherBox relay (not BYO node) because
      // they're staged for the replacement dialog. Once the user confirms, the
      // replacement flow uses SDK's uploadFile() which respects pinning mode.
      if (duplicateFiles.length > 0) {
        const replacements: PendingReplacement[] = [];

        // Hoist dynamic import before the loop to avoid per-iteration async overhead
        const { encryptFile } = await import('../services/file-crypto.service');

        for (const file of duplicateFiles) {
          const uploadId = createUploadId(file.name);
          currentDupUploadId = uploadId;
          useUploadStore.getState().addFile(uploadId, file.name, folderId, file);

          if (!useUploadStore.getState().files.get(uploadId)) {
            throw new Error('Upload cancelled by user');
          }

          // For duplicates, we only encrypt + upload to IPFS (don't register in folder)
          // Use the old upload service for this since SDK's uploadFile registers in folder
          const userPublicKey = useAuthStore.getState().vaultKeypair?.publicKey;
          if (!userPublicKey) throw new Error('No keypair available');
          const encrypted = await encryptFile(file, userPublicKey);

          // SDK facade's uploadBytes takes the Uint8Array directly -- no Blob
          // construction needed here (D-07; the facade doesn't currently accept
          // a cancel token, 68.2-03 scope -- a known limitation vs. the prior
          // direct raw-IPFS-upload + cancelToken path).
          const ipfsResult = await client.uploadBytes(encrypted.ciphertext, (percent) =>
            useUploadStore.getState().updateFileProgress(uploadId, percent)
          );

          orphanCids.push(ipfsResult.cid);
          useUploadStore.getState().setFileStatus(uploadId, 'complete');

          const existingFileId = existingByName.get(file.name);
          if (existingFileId) {
            replacements.push({
              fileName: file.name,
              fileId: existingFileId,
              parentId: folderId,
              encryptedData: {
                cid: ipfsResult.cid,
                wrappedKey: encrypted.wrappedKey,
                iv: encrypted.iv,
                size: file.size,
                encryptionMode: encrypted.encryptionMode,
              },
            });
          }
        }

        if (replacements.length > 0) {
          useUploadStore.getState().setPendingReplacements(replacements);
        }
      }

      return true;
    } catch (err) {
      const message = (err as Error).message;
      if (message !== 'Upload cancelled by user' && currentDupUploadId) {
        useUploadStore.getState().setFileStatus(currentDupUploadId, 'error', message);
      }
      // Best-effort cleanup: unpin orphaned CIDs from failed upload via the SDK facade (D-07)
      if (orphanCids.length > 0) {
        for (const cid of orphanCids) {
          client.unpin(cid).catch((err) => logger.warn('[Upload] Unpin orphaned CID failed:', err));
        }
      }
      return false;
    } finally {
      // Refresh quota from server
      await useQuotaStore.getState().fetchQuota();
    }
  }, []);

  return { handleFileDrop, isUploading };
}
