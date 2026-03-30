import { encryptFile, EncryptedFileResult } from './file-crypto.service';
import { addToIpfs, AddResponse } from '../lib/api/ipfs';
import { useQuotaStore } from '../stores/quota.store';
import { useUploadStore } from '../stores/upload.store';
import { CancelToken } from 'axios';
import { logger } from '../lib/logger';

const MAX_RETRIES = 3;
const RETRY_BASE_DELAY = 500;

export type UploadedFile = {
  cid: string;
  size: number;
  iv: string;
  wrappedKey: string;
  originalName: string;
  originalSize: number;
  encryptionMode: 'GCM' | 'CTR';
};

/**
 * Retry wrapper with exponential backoff.
 * Does not retry cancelled operations.
 */
async function withRetry<T>(
  fn: () => Promise<T>,
  maxRetries: number = MAX_RETRIES,
  baseDelay: number = RETRY_BASE_DELAY
): Promise<T> {
  let lastError: Error = new Error('Retry failed');

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      // Don't retry if cancelled
      if ((error as Error).message === 'Upload cancelled by user') {
        throw error;
      }
      if (attempt < maxRetries - 1) {
        const delay = baseDelay * Math.pow(2, attempt);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }

  throw lastError;
}

/**
 * Upload a single file: encrypt then upload to IPFS.
 */
export async function uploadFile(
  file: File,
  userPublicKey: Uint8Array,
  onProgress?: (percent: number) => void,
  cancelToken?: CancelToken
): Promise<UploadedFile> {
  // 1. Encrypt the file
  const encrypted: EncryptedFileResult = await encryptFile(file, userPublicKey);

  // 2. Upload to IPFS with retry
  // Cast to ArrayBuffer for TypeScript 5.9 compatibility (Uint8Array.buffer is ArrayBufferLike)
  const blob = new Blob([encrypted.ciphertext.buffer as ArrayBuffer], {
    type: 'application/octet-stream',
  });
  const result: AddResponse = await withRetry(() => addToIpfs(blob, onProgress, cancelToken));

  return {
    cid: result.cid,
    size: result.size,
    iv: encrypted.iv,
    wrappedKey: encrypted.wrappedKey,
    originalName: file.name,
    originalSize: encrypted.originalSize,
    encryptionMode: encrypted.encryptionMode,
  };
}

/**
 * Upload multiple files sequentially.
 * Pre-checks quota and tracks progress via upload store (per-file tracking).
 */
export async function uploadFiles(
  files: File[],
  userPublicKey: Uint8Array
): Promise<UploadedFile[]> {
  const quotaStore = useQuotaStore.getState();

  // Calculate total size
  const totalSize = files.reduce((sum, f) => sum + f.size, 0);

  // Pre-check quota
  if (!quotaStore.canUpload(totalSize)) {
    throw new Error(
      `Not enough space (${Math.round(quotaStore.usedBytes / 1024 / 1024)} of ${Math.round(quotaStore.limitBytes / 1024 / 1024)}MB used)`
    );
  }

  const results: UploadedFile[] = [];

  try {
    // Sequential uploads per CONTEXT.md decision
    for (const file of files) {
      const uploadId = `upload-${file.name}-${Date.now()}`;
      useUploadStore.getState().addFile(uploadId, file.name, '', file);

      const cancelSource = useUploadStore.getState().files.get(uploadId)?.cancelSource;
      if (useUploadStore.getState().files.get(uploadId)?.status === 'cancelled') {
        throw new Error('Upload cancelled by user');
      }

      const result = await uploadFile(
        file,
        userPublicKey,
        (percent) => useUploadStore.getState().updateFileProgress(uploadId, percent),
        cancelSource?.token
      );

      results.push(result);
      useUploadStore.getState().setFileComplete(uploadId);
    }

    return results;
  } catch (error) {
    const message = (error as Error).message;
    if (message !== 'Upload cancelled by user') {
      logger.error('[Upload] Upload failed:', error);
    }
    throw error;
  } finally {
    // Refresh quota from server (authoritative source after atomic upload)
    await useQuotaStore.getState().fetchQuota();
  }
}
