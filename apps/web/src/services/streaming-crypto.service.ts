/**
 * Streaming Crypto Service - Mode selection and AES-256-CTR streaming encryption
 *
 * Media files above 256KB are encrypted with AES-256-CTR using streaming 1MB chunks,
 * which keeps memory bounded regardless of file size. CTR mode produces ciphertext
 * that supports random-access decryption for streaming media playback.
 *
 * Non-media files and small media files continue using AES-256-GCM via the
 * existing file-crypto.service.ts path.
 */

import {
  generateFileKey,
  generateCtrIv,
  wrapKey,
  clearBytes,
  bytesToHex,
  AES_CTR_LENGTH,
  AES_CTR_NONCE_SIZE,
} from '@cipherbox/crypto';

import type { EncryptedFileResult } from './file-crypto.service';

/** MIME types eligible for CTR streaming encryption */
const STREAMING_MIME_TYPES = new Set([
  'video/mp4',
  'video/webm',
  'audio/mpeg',
  'audio/mp4',
  'audio/webm',
  'audio/ogg',
  'audio/aac',
]);

/** Minimum file size (bytes) to use CTR mode: 256KB */
const CTR_SIZE_THRESHOLD = 256 * 1024;

/** Chunk size for streaming encryption: 1MB */
const CHUNK_SIZE = 1024 * 1024;

/** AES-CTR algorithm name */
const AES_CTR_ALGORITHM = 'AES-CTR';

/**
 * Select encryption mode based on file MIME type and size.
 *
 * Returns 'CTR' for media files above 256KB (streaming media benefits from
 * random-access decryption). All other files use 'GCM' for authenticated encryption.
 *
 * @param file - File to classify
 * @returns 'CTR' for streaming media, 'GCM' for everything else
 */
export function selectEncryptionMode(file: File): 'GCM' | 'CTR' {
  if (STREAMING_MIME_TYPES.has(file.type) && file.size > CTR_SIZE_THRESHOLD) {
    return 'CTR';
  }
  return 'GCM';
}

/**
 * Encrypt a file using AES-256-CTR in streaming 1MB chunks.
 *
 * The file is read in CHUNK_SIZE slices, each encrypted with a counter
 * derived from its byte offset. This keeps memory bounded to ~2MB
 * (one input chunk + one output chunk) regardless of file size.
 *
 * CTR ciphertext is the same size as plaintext (no auth tag overhead).
 * Integrity is provided by IPFS content addressing.
 *
 * @param file - File to encrypt
 * @param userPublicKey - User's secp256k1 public key (65 bytes, uncompressed)
 * @returns Encrypted file data with wrapped key and IV
 */
export async function encryptFileCtr(
  file: File,
  userPublicKey: Uint8Array
): Promise<EncryptedFileResult> {
  // 1. Generate unique file key and CTR IV
  const fileKey = generateFileKey();
  const iv = generateCtrIv();

  // 2. Import CryptoKey once (not per-chunk)
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(fileKey).buffer as ArrayBuffer,
    { name: AES_CTR_ALGORITHM },
    false,
    ['encrypt']
  );

  // 3. Stream-encrypt file in 1MB chunks
  const encryptedChunks: Uint8Array[] = [];
  let offset = 0;

  while (offset < file.size) {
    const end = Math.min(offset + CHUNK_SIZE, file.size);
    const chunk = new Uint8Array(await file.slice(offset, end).arrayBuffer());

    // Compute counter for this chunk's byte offset
    const blockOffset = Math.floor(offset / 16);
    const counter = new Uint8Array(16);
    // Copy first 8 bytes of IV (nonce)
    counter.set(iv.subarray(0, AES_CTR_NONCE_SIZE), 0);
    // Set bytes 8-15 to blockOffset as big-endian uint64
    const dv = new DataView(counter.buffer);
    dv.setBigUint64(8, BigInt(blockOffset), false);

    const encrypted = await crypto.subtle.encrypt(
      { name: AES_CTR_ALGORITHM, counter, length: AES_CTR_LENGTH },
      cryptoKey,
      chunk
    );

    encryptedChunks.push(new Uint8Array(encrypted));
    offset = end;
  }

  // 4. Combine encrypted chunks into single Uint8Array
  const totalSize = encryptedChunks.reduce((sum, c) => sum + c.length, 0);
  const ciphertext = new Uint8Array(totalSize);
  let writeOffset = 0;
  for (const chunk of encryptedChunks) {
    ciphertext.set(chunk, writeOffset);
    writeOffset += chunk.length;
  }

  // 5. Wrap file key with user's public key (ECIES)
  const wrappedKey = await wrapKey(fileKey, userPublicKey);

  // 6. Clear sensitive key from memory
  clearBytes(fileKey);

  return {
    ciphertext,
    iv: bytesToHex(iv),
    wrappedKey: bytesToHex(wrappedKey),
    originalSize: file.size,
    encryptedSize: file.size, // CTR: same size as plaintext (no auth tag)
    encryptionMode: 'CTR' as const,
  };
}
