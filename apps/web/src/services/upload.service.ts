import { encryptFile, EncryptedFileResult } from './file-crypto.service';
import { addToIpfs, AddResponse } from '../lib/api/ipfs';
import { CancelToken } from 'axios';

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
