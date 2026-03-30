/**
 * Upload operations - Encrypt and upload files to IPFS
 *
 * Extracted from: apps/web/src/services/upload.service.ts + file-crypto.service.ts
 * Change: Takes raw Uint8Array data instead of File objects (no browser DOM deps).
 * Change: Takes explicit SdkContext instead of reading stores.
 * Does NOT handle: multi-file orchestration, upload queue, progress UI, quota checking.
 */

import {
  generateFileKey,
  generateIv,
  generateCtrIv,
  encryptAesGcm,
  encryptAesCtr,
  wrapKey,
  clearBytes,
  bytesToHex,
} from '@cipherbox/crypto';
import type { SdkContext, TeeKeys, ProgressCallback } from '../types';
import { addToIpfs } from '../ipfs';
import { createFileMetadata, type FileIpnsRecordPayload } from '../file';
import { normalizeEncryptionMode } from '../encryption-mode';
import { withPerf } from '../perf';

/**
 * External encryption function type for Web Worker offloading.
 * When provided to uploadFile(), replaces internal AES encrypt + key wrap steps.
 * Must return ciphertext, hex-encoded wrappedKey/iv, and raw fileKey for re-wrapping.
 */
export type ExternalEncryptFn = (params: {
  data: Uint8Array;
  userPublicKey: Uint8Array;
  encryptionMode: 'GCM' | 'CTR';
}) => Promise<{
  ciphertext: Uint8Array;
  wrappedKey: string;
  iv: string;
  fileKey: Uint8Array;
  originalSize: number;
  encryptedSize: number;
}>;

/**
 * Result of a single file upload operation.
 */
export type UploadResult = {
  /** IPFS CID of the encrypted file content */
  cid: string;
  /** Encrypted file size in bytes */
  encryptedSize: number;
  /** File metadata IPNS name (for FilePointer) */
  fileMetaIpnsName: string;
  /** File IPNS record payload for batch publish */
  ipnsRecord: FileIpnsRecordPayload;
  /** ECIES-wrapped IPNS private key (hex) for storage in FilePointer */
  ipnsPrivateKeyEncrypted: string;
  /**
   * Plaintext file key (AES-256) for post-upload re-wrapping.
   * The caller MUST clear this with clearBytes() after use.
   * Only present when the caller needs to re-wrap for share recipients.
   */
  fileKey: Uint8Array;
};

/**
 * Encrypt and upload a file to IPFS, creating file metadata.
 *
 * This is the core single-file upload pipeline:
 * 1. Generate file key + IV
 * 2. Encrypt the file content with AES-256-GCM
 * 3. Upload encrypted blob to IPFS
 * 4. Create per-file IPNS metadata record
 *
 * Returns everything needed to add a FilePointer to the parent folder.
 *
 * @param params.data - Raw file content as Uint8Array
 * @param params.fileId - Pre-generated UUID for this file
 * @param params.mimeType - MIME type of the original file
 * @param params.folderKey - Parent folder's decrypted AES-256 key
 * @param params.userPublicKey - User's secp256k1 public key for ECIES wrapping
 * @param params.ctx - SDK context for API access
 * @param params.onProgress - Optional upload progress callback
 * @param params.teeKeys - Optional TEE keys for IPNS private key enrollment
 */
export async function uploadFile(params: {
  data: Uint8Array;
  fileId: string;
  mimeType: string;
  folderKey: Uint8Array;
  userPublicKey: Uint8Array;
  ctx: SdkContext;
  onProgress?: ProgressCallback;
  teeKeys?: TeeKeys;
  /** Override the default addToIpfs pin function. Used by BYO-IPFS to pin directly to user's node. */
  pinFn?: (
    ctx: SdkContext,
    data: Uint8Array,
    onProgress?: ProgressCallback
  ) => Promise<{ cid: string; size: number }>;
  /** Encryption mode: GCM (default, authenticated) or CTR (streaming media). */
  encryptionMode?: 'GCM' | 'CTR';
  /** Optional external encryption function (e.g., Web Worker). If provided, skips internal AES encrypt.
   * Must return ciphertext, hex-encoded wrappedKey, hex-encoded iv, and raw fileKey for re-wrapping. */
  encryptFn?: ExternalEncryptFn;
}): Promise<UploadResult> {
  return withPerf('upload:full', async () => {
    const mode = normalizeEncryptionMode(params.encryptionMode);

    // Capture original size before any Transferable detachment (encryptFn may
    // transfer params.data.buffer to a Worker, making params.data.length = 0)
    const originalSize = params.data.length;

    // Internal file key -- only generated when encryptFn is NOT provided.
    // When encryptFn is provided, the caller owns the returned fileKey memory.
    let fileKeyInternal: Uint8Array | null = null;

    try {
      let ciphertext: Uint8Array;
      let wrappedKeyHex: string;
      let ivHex: string;
      let fileKeyForResult: Uint8Array;

      if (params.encryptFn) {
        // External encryption path (e.g., Web Worker)
        const extResult = await params.encryptFn({
          data: params.data,
          userPublicKey: params.userPublicKey,
          encryptionMode: mode,
        });
        ciphertext = extResult.ciphertext;
        wrappedKeyHex = extResult.wrappedKey;
        ivHex = extResult.iv;
        fileKeyForResult = extResult.fileKey;
      } else {
        // Internal encryption path (original behavior)
        // 1. Generate unique file key and IV (CTR uses 16-byte nonce+counter, GCM uses 12-byte random)
        fileKeyInternal = generateFileKey();
        const iv = mode === 'CTR' ? generateCtrIv() : generateIv();

        // 2. Encrypt file content
        ciphertext =
          mode === 'CTR'
            ? await encryptAesCtr(params.data, fileKeyInternal, iv)
            : await encryptAesGcm(params.data, fileKeyInternal, iv);

        // 3. Wrap file key with user's public key (ECIES)
        const wrappedKey = await wrapKey(fileKeyInternal, params.userPublicKey);
        wrappedKeyHex = bytesToHex(wrappedKey);
        ivHex = bytesToHex(iv);

        // Return a defensive copy of the file key for re-wrapping.
        // The caller is responsible for clearing it after use.
        fileKeyForResult = new Uint8Array(fileKeyInternal);
      }

      // 4. Upload encrypted content to IPFS (or BYO node via pinFn override)
      const pinResult = params.pinFn
        ? await withPerf('ipfs:upload:byo', () =>
            params.pinFn!(params.ctx, ciphertext, params.onProgress)
          )
        : await addToIpfs(params.ctx, ciphertext, params.onProgress);
      const { cid, size: encryptedSize } = pinResult;

      // 5. Create per-file IPNS metadata record
      const fileMetaResult = await createFileMetadata({
        fileId: params.fileId,
        cid,
        fileKeyEncrypted: wrappedKeyHex,
        fileIv: ivHex,
        size: originalSize,
        mimeType: params.mimeType,
        folderKey: params.folderKey,
        userPublicKey: params.userPublicKey,
        ctx: params.ctx,
        teeKeys: params.teeKeys,
        encryptionMode: mode,
      });

      return {
        cid,
        encryptedSize,
        fileMetaIpnsName: fileMetaResult.fileMetaIpnsName,
        ipnsRecord: fileMetaResult.ipnsRecord,
        ipnsPrivateKeyEncrypted: fileMetaResult.ipnsPrivateKeyEncrypted,
        fileKey: fileKeyForResult,
      };
    } finally {
      // 6. Clear the internal copy of the key from memory (only if internally generated)
      if (fileKeyInternal) {
        clearBytes(fileKeyInternal);
      }
    }
  });
}
