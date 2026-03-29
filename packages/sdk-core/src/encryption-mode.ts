/**
 * Encryption mode selection for file uploads.
 *
 * Centralizes the policy for choosing AES-CTR vs AES-GCM so that
 * all upload paths (SDK client, web app duplicate-file path) use
 * the same MIME type list and size threshold.
 */

/** MIME types eligible for CTR streaming encryption */
const STREAMING_MIME_TYPES = new Set([
  'video/mp4',
  'video/webm',
  'audio/mpeg',
  'audio/mp4',
  'audio/webm',
  'audio/ogg',
  'audio/aac',
  'audio/flac',
]);

/** Minimum file size (bytes) to use CTR mode: 256KB */
const CTR_SIZE_THRESHOLD = 256 * 1024;

export type EncryptionMode = 'GCM' | 'CTR';

/**
 * Select encryption mode based on MIME type and file size.
 *
 * Media files above 256KB use AES-256-CTR for random-access streaming
 * decryption via Service Worker. All other files use AES-256-GCM for
 * authenticated encryption.
 */
export function selectEncryptionMode(mimeType: string, size: number): EncryptionMode {
  if (STREAMING_MIME_TYPES.has(mimeType) && size > CTR_SIZE_THRESHOLD) {
    return 'CTR';
  }
  return 'GCM';
}

/**
 * Validate and normalize an encryption mode value.
 *
 * Coerces any non-'CTR' value to 'GCM' so that invalid input from
 * JS consumers never propagates into file metadata.
 */
export function normalizeEncryptionMode(mode: string | undefined): EncryptionMode {
  return mode === 'CTR' ? 'CTR' : 'GCM';
}
