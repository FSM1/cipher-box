import { decryptAesGcm, unwrapKey, hexToBytes, clearBytes } from '@cipherbox/crypto';
import { fetchFromIpfs, DownloadProgressCallback } from '../lib/api/ipfs';
import { UploadedFile } from './upload.service';

/**
 * File metadata required for download and decryption.
 * This matches the UploadedFile type but only needs the fields for download.
 */
export type FileMetadata = Pick<UploadedFile, 'cid' | 'iv' | 'wrappedKey' | 'originalName'>;

/**
 * Downloads and decrypts a file from IPFS.
 *
 * @param metadata - File metadata containing CID, IV, and wrapped key
 * @param privateKey - User's private key for unwrapping the file key
 * @param onProgress - Optional progress callback (loaded, total bytes)
 * @returns Decrypted file content
 */
export async function downloadFile(
  metadata: FileMetadata,
  privateKey: Uint8Array,
  onProgress?: DownloadProgressCallback
): Promise<Uint8Array> {
  // 1. Fetch encrypted file from IPFS
  const ciphertext = await fetchFromIpfs(metadata.cid, onProgress);

  // 2. Convert hex strings to bytes
  const iv = hexToBytes(metadata.iv);
  const wrappedKey = hexToBytes(metadata.wrappedKey);

  // 3. Unwrap file key using user's private key
  const fileKey = await unwrapKey(wrappedKey, privateKey);

  try {
    // 4. Decrypt file content
    const plaintext = await decryptAesGcm(ciphertext, fileKey, iv);
    return plaintext;
  } finally {
    // 5. Clear file key from memory
    clearBytes(fileKey);
  }
}

/**
 * Triggers browser download dialog for decrypted content.
 *
 * @param content - Decrypted file content
 * @param filename - Original filename
 * @param mimeType - Optional MIME type (defaults to octet-stream)
 */
export function triggerBrowserDownload(
  content: Uint8Array,
  filename: string,
  mimeType: string = 'application/octet-stream'
): void {
  // Cast to ArrayBuffer for TypeScript 5.9 compatibility (Uint8Array.buffer is ArrayBufferLike)
  const blob = new Blob([content.buffer as ArrayBuffer], { type: mimeType });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  // Clean up blob URL
  URL.revokeObjectURL(url);
}

/**
 * Downloads, decrypts, and triggers browser download for a file.
 *
 * @param metadata - File metadata
 * @param privateKey - User's private key
 * @param onProgress - Optional progress callback
 */
export async function downloadAndSaveFile(
  metadata: FileMetadata,
  privateKey: Uint8Array,
  onProgress?: DownloadProgressCallback
): Promise<void> {
  const plaintext = await downloadFile(metadata, privateKey, onProgress);
  triggerBrowserDownload(plaintext, metadata.originalName);
}
