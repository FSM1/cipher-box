/**
 * Download operations - Fetch and decrypt files from IPFS
 *
 * Extracted from: apps/web/src/services/download.service.ts
 * Change: Takes SdkContext for IPFS access.
 * Does NOT handle: browser download trigger (document.createElement, URL.createObjectURL).
 */

import { decryptAesGcm, decryptAesCtr, unwrapKey, hexToBytes, clearBytes } from '@cipherbox/crypto';
import type { SdkContext, DownloadProgressCallback } from '../types';
import { fetchFromIpfs } from '../ipfs';

/**
 * Download and decrypt a file from IPFS.
 *
 * Fetches the encrypted file content from IPFS via the backend relay,
 * unwraps the file key, and decrypts the content.
 *
 * @param params.cid - IPFS CID of the encrypted file content
 * @param params.fileKeyEncrypted - Hex-encoded ECIES-wrapped file key
 * @param params.fileIv - Hex-encoded IV used for encryption
 * @param params.userPrivateKey - User's secp256k1 private key for key unwrapping
 * @param params.encryptionMode - Encryption mode: 'GCM' (default) or 'CTR'
 * @param params.ctx - SDK context for IPFS access
 * @param params.onProgress - Optional download progress callback
 * @returns Decrypted file content as Uint8Array
 */
export async function downloadAndDecrypt(params: {
  cid: string;
  fileKeyEncrypted: string;
  fileIv: string;
  userPrivateKey: Uint8Array;
  encryptionMode?: 'GCM' | 'CTR';
  ctx: SdkContext;
  onProgress?: DownloadProgressCallback;
}): Promise<Uint8Array> {
  // 1. Fetch encrypted file from IPFS
  const ciphertext = await fetchFromIpfs(params.ctx, params.cid, params.onProgress);

  // 2. Convert hex strings to bytes
  const iv = hexToBytes(params.fileIv);
  const wrappedKey = hexToBytes(params.fileKeyEncrypted);

  // 3. Unwrap file key using user's private key
  const fileKey = await unwrapKey(wrappedKey, params.userPrivateKey);

  try {
    // 4. Decrypt file content (CTR for streaming media, GCM for everything else)
    const plaintext =
      params.encryptionMode === 'CTR'
        ? await decryptAesCtr(ciphertext, fileKey, iv)
        : await decryptAesGcm(ciphertext, fileKey, iv);
    return plaintext;
  } finally {
    // 5. Clear file key from memory
    clearBytes(fileKey);
  }
}
