import { encryptFile, EncryptedFileResult } from './file-crypto.service';
import { getSdkClient } from '../lib/sdk-provider';

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
 * Upload a single file: encrypt then upload to IPFS via the SDK's
 * IPFS-transport facade (D-07, `client.uploadBytes`). Progress is threaded
 * through verbatim; the facade does not currently accept a cancel token
 * (68.2-03 scope) -- this function has no production callers today (only
 * the `UploadedFile` type is reused by `download.service.ts`), so that is
 * not a live regression.
 */
export async function uploadFile(
  file: File,
  userPublicKey: Uint8Array,
  onProgress?: (percent: number) => void
): Promise<UploadedFile> {
  // 1. Encrypt the file
  const encrypted: EncryptedFileResult = await encryptFile(file, userPublicKey);

  // 2. Upload to IPFS with retry via the SDK facade (uploadBytes takes the
  // Uint8Array directly -- no Blob construction needed here).
  const result = await withRetry(() =>
    getSdkClient().uploadBytes(encrypted.ciphertext, onProgress)
  );

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
