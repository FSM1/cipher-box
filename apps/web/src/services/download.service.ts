import { decryptAesGcm, decryptAesCtr, unwrapKey, hexToBytes, clearBytes } from '@cipherbox/crypto';
import type { SealedChildRef } from '@cipherbox/core';
import type { DownloadProgressCallback } from '@cipherbox/sdk-core';
import { getSdkClient } from '../lib/sdk-provider';
import { UploadedFile } from './upload.service';

/** Decodes a base64 string to a Uint8Array (NodeContent.fileIv is base64, v3 contract). */
function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

/**
 * File metadata required for download and decryption.
 * This matches the UploadedFile type but only needs the fields for download.
 */
export type FileMetadata = Pick<UploadedFile, 'cid' | 'iv' | 'wrappedKey' | 'originalName'> & {
  /** Encryption mode: 'GCM' (default) or 'CTR' (streaming media) */
  encryptionMode?: 'GCM' | 'CTR';
};

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
  // 1. Fetch encrypted file from IPFS via the SDK's IPFS-transport facade (D-07)
  const ciphertext = await getSdkClient().downloadBytes(metadata.cid, onProgress);

  // 2. Convert hex strings to bytes
  const iv = hexToBytes(metadata.iv);
  const wrappedKey = hexToBytes(metadata.wrappedKey);

  // 3. Unwrap file key using user's private key
  const fileKey = await unwrapKey(wrappedKey, privateKey);

  try {
    // 4. Decrypt file content (CTR for streaming media, GCM for everything else)
    const plaintext =
      metadata.encryptionMode === 'CTR'
        ? await decryptAesCtr(ciphertext, fileKey, iv)
        : await decryptAesGcm(ciphertext, fileKey, iv);
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
  // Cast needed for TS 5.9 where Uint8Array<ArrayBufferLike> isn't assignable to BlobPart
  const blob = new Blob([content as BlobPart], { type: mimeType });
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

/**
 * Download and decrypt a file using its per-file Node content (node/v3 read-chain).
 *
 * Resolves the file's `NodeContent` via `client.resolveFileMetadata` (68.2-11 SDK
 * facade; readKey recovered from `fileRef.readKeySealed` under the parent
 * `folderKey`), fetches the content CID, then decrypts with the RAW fileKey
 * recovered inside `NodeContent.fileKey` — NOT the legacy ECIES
 * `downloadAndDecrypt`/`unwrapKey` path. `NodeContent.fileIv` is base64-encoded
 * (v3 contract; NOT hex like the legacy `FileMetadata.iv`).
 *
 * @security `metadata.fileKey` originates from `resolveFileMetadata`'s freshly
 *   unsealed `NodeContent` — this function is its terminal consumer and zeroes it
 *   after decrypt (D-09). Does NOT touch `folderKey` (caller-owned).
 */
export async function downloadFileFromIpns(params: {
  fileRef: SealedChildRef;
  folderKey: Uint8Array;
  onProgress?: DownloadProgressCallback;
}): Promise<Uint8Array> {
  const client = getSdkClient();
  const { metadata } = await client.resolveFileMetadata(params.fileRef, params.folderKey);

  const ciphertext = await client.downloadBytes(metadata.cid, params.onProgress);
  const iv = base64ToBytes(metadata.fileIv);
  const fileKey = metadata.fileKey;

  try {
    return metadata.encryptionMode === 'CTR'
      ? await decryptAesCtr(ciphertext, fileKey, iv)
      : await decryptAesGcm(ciphertext, fileKey, iv);
  } finally {
    // metadata.fileKey is this function's terminal-consumption point (D-09) —
    // zero it once decrypt completes on every exit path.
    clearBytes(fileKey);
  }
}
