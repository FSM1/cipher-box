import { useCallback } from 'react';
import { logger } from '../lib/logger';
import { useUploadStore, createUploadId } from '../stores/upload.store';
import { useQuotaStore } from '../stores/quota.store';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useAuthStore } from '../stores/auth.store';
import { getSdkClient, hasSdkClient, ensureFolderRegistered } from '../lib/sdk-provider';
import { getRootFolderState } from './folder-helpers';
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
 * Uses the SDK's uploadFile() for atomic encrypt -> upload -> register flow.
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
    const folder = useFolderStore.getState().folders[folderId];
    const existingByName = new Map<string, string>(); // name -> fileId
    const existingFolderNames = new Set<string>();
    if (folder) {
      for (const child of folder.children) {
        if (child.type === 'file') {
          existingByName.set(child.name, child.id);
        } else if (child.type === 'folder') {
          existingFolderNames.add(child.name);
        }
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

    // Resolve parent folder and ensure it's registered in the SDK
    const folders = useFolderStore.getState().folders;
    const vault = useVaultStore.getState();
    const parentFolder =
      folderId === 'root' ? getRootFolderState(vault, folders) : folders[folderId];
    if (!parentFolder) {
      logger.error('[Upload] Parent folder not found');
      return false;
    }
    ensureFolderRegistered(parentFolder);

    const orphanCids: string[] = []; // Only unregistered CIDs (duplicates staged for replacement)
    let currentUploadId: string | undefined;

    try {
      // Upload new files via SDK (atomic: encrypt -> IPFS -> FilePointer -> IPNS publish)
      for (const file of newFiles) {
        const uploadId = createUploadId(file.name);
        currentUploadId = uploadId;
        useUploadStore.getState().addFile(uploadId, file.name, folderId, file);

        if (!useUploadStore.getState().files.get(uploadId)) {
          throw new Error('Upload cancelled by user');
        }

        const data = new Uint8Array(await file.arrayBuffer());

        await client.uploadFile(
          parentFolder.ipnsName,
          data,
          file.name,
          file.type || 'application/octet-stream',
          (percent) => useUploadStore.getState().updateFileProgress(uploadId, percent)
        );

        useUploadStore.getState().setFileStatus(uploadId, 'complete');
      }

      // Handle duplicate files: encrypt + upload to IPFS, then surface as pending replacements
      // (These don't get registered in the folder -- the user decides via the Replace dialog)
      // Duplicate files always upload to CipherBox relay (not BYO node) because
      // they're staged for the replacement dialog. Once the user confirms, the
      // replacement flow uses SDK's uploadFile() which respects pinning mode.
      if (duplicateFiles.length > 0) {
        const replacements: PendingReplacement[] = [];

        // Hoist dynamic imports before the loop to avoid per-iteration async overhead
        const { encryptFile } = await import('../services/file-crypto.service');
        const { addToIpfs } = await import('../lib/api/ipfs');

        for (const file of duplicateFiles) {
          const uploadId = createUploadId(file.name);
          currentUploadId = uploadId;
          useUploadStore.getState().addFile(uploadId, file.name, folderId, file);

          if (!useUploadStore.getState().files.get(uploadId)) {
            throw new Error('Upload cancelled by user');
          }

          // For duplicates, we only encrypt + upload to IPFS (don't register in folder)
          // Use the old upload service for this since SDK's uploadFile registers in folder
          const userPublicKey = useAuthStore.getState().vaultKeypair?.publicKey;
          if (!userPublicKey) throw new Error('No keypair available');
          const encrypted = await encryptFile(file, userPublicKey);
          // Pass a clean Uint8Array copy -- never use .buffer (may include extra bytes)
          const blob = new Blob([new Uint8Array(encrypted.ciphertext)], {
            type: 'application/octet-stream',
          });

          const cancelToken = useUploadStore.getState().files.get(uploadId)?.cancelSource?.token;
          const ipfsResult = await addToIpfs(
            blob,
            (percent) => useUploadStore.getState().updateFileProgress(uploadId, percent),
            cancelToken
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
      if (message !== 'Upload cancelled by user' && currentUploadId) {
        useUploadStore.getState().setFileStatus(currentUploadId, 'error', message);
      }
      // Best-effort cleanup: unpin orphaned CIDs from failed upload
      if (orphanCids.length > 0) {
        import('../lib/api/ipfs')
          .then(({ unpinFromIpfs }) => {
            for (const cid of orphanCids) {
              unpinFromIpfs(cid).catch((err) =>
                logger.warn('[Upload] Unpin orphaned CID failed:', err)
              );
            }
          })
          .catch((err) => logger.warn('[Upload] Failed to load IPFS module for cleanup:', err));
      }
      return false;
    } finally {
      // Refresh quota from server
      await useQuotaStore.getState().fetchQuota();
    }
  }, []);

  return { handleFileDrop, isUploading };
}
