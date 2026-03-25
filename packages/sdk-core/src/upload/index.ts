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
  encryptAesGcm,
  wrapKey,
  clearBytes,
  bytesToHex,
} from '@cipherbox/crypto';
import type { SdkContext, TeeKeys, ProgressCallback } from '../types';
import { addToIpfs } from '../ipfs';
import { createFileMetadata, type FileIpnsRecordPayload } from '../file';
import { withPerf } from '../perf';

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
}): Promise<UploadResult> {
  return withPerf('upload:full', async () => {
    // 1. Generate unique file key and IV
    const fileKey = generateFileKey();
    const iv = generateIv();

    try {
      // 2. Encrypt with AES-256-GCM
      const ciphertext = await encryptAesGcm(params.data, fileKey, iv);

      // 3. Wrap file key with user's public key (ECIES)
      const wrappedKey = await wrapKey(fileKey, params.userPublicKey);

      // 4. Upload encrypted content to IPFS (or BYO node via pinFn override)
      const pinResult = params.pinFn
        ? await params.pinFn(params.ctx, ciphertext, params.onProgress)
        : await addToIpfs(params.ctx, ciphertext, params.onProgress);
      const { cid, size: encryptedSize } = pinResult;

      // 5. Create per-file IPNS metadata record
      const fileMetaResult = await createFileMetadata({
        fileId: params.fileId,
        cid,
        fileKeyEncrypted: bytesToHex(wrappedKey),
        fileIv: bytesToHex(iv),
        size: params.data.length,
        mimeType: params.mimeType,
        folderKey: params.folderKey,
        userPublicKey: params.userPublicKey,
        ctx: params.ctx,
        teeKeys: params.teeKeys,
        encryptionMode: 'GCM',
      });

      // Return a defensive copy of the file key for re-wrapping.
      // The caller is responsible for clearing it after use.
      const fileKeyCopy = new Uint8Array(fileKey);

      return {
        cid,
        encryptedSize,
        fileMetaIpnsName: fileMetaResult.fileMetaIpnsName,
        ipnsRecord: fileMetaResult.ipnsRecord,
        ipnsPrivateKeyEncrypted: fileMetaResult.ipnsPrivateKeyEncrypted,
        fileKey: fileKeyCopy,
      };
    } finally {
      // 6. Clear the internal copy of the key from memory
      clearBytes(fileKey);
    }
  });
}
