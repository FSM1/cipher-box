/**
 * @cipherbox/crypto - AES-256-CTR Decryption
 *
 * Symmetric decryption for media file content using CTR mode.
 * Supports both full-buffer and random-access range decryption.
 *
 * Random-access decryption (decryptAesCtrRange) enables the Service Worker
 * to decrypt arbitrary byte ranges without processing preceding bytes,
 * which is critical for streaming media playback with seek support.
 *
 * Uses Web Crypto API for hardware-accelerated decryption.
 */

import { CryptoError } from '../types';
import { AES_KEY_SIZE, AES_CTR_IV_SIZE, AES_CTR_ALGORITHM, AES_CTR_LENGTH } from '../constants';

/**
 * Decrypt data encrypted with AES-256-CTR.
 *
 * @param ciphertext - Encrypted data (same size as original plaintext)
 * @param key - 32-byte AES key (must match encryption key)
 * @param iv - 16-byte counter block (must match encryption IV)
 * @returns Decrypted plaintext
 * @throws CryptoError with generic message on any failure
 */
export async function decryptAesCtr(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  // Validate key size
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError('Decryption failed', 'INVALID_KEY_SIZE');
  }

  // Validate IV size
  if (iv.length !== AES_CTR_IV_SIZE) {
    throw new CryptoError('Decryption failed', 'INVALID_IV_SIZE');
  }

  try {
    // Copy to ensure proper ArrayBuffer (not SharedArrayBuffer)
    const keyBuffer = new Uint8Array(key).buffer as ArrayBuffer;
    const ivBuffer = new Uint8Array(iv);
    const ciphertextBuffer = new Uint8Array(ciphertext).buffer as ArrayBuffer;

    // Import key for decryption
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: AES_CTR_ALGORITHM },
      false,
      ['decrypt']
    );

    // Decrypt - CTR mode decrypt is identical to encrypt (XOR is symmetric)
    const plaintext = await crypto.subtle.decrypt(
      { name: AES_CTR_ALGORITHM, counter: ivBuffer, length: AES_CTR_LENGTH },
      cryptoKey,
      ciphertextBuffer
    );

    return new Uint8Array(plaintext);
  } catch {
    // Generic error to prevent oracle attacks
    throw new CryptoError('Decryption failed', 'DECRYPTION_FAILED');
  }
}

/**
 * Decrypt an arbitrary byte range from AES-256-CTR encrypted data.
 *
 * This is the critical function for Service Worker streaming media playback.
 * It computes the correct counter value for any byte offset and decrypts
 * only the required blocks, avoiding the need to process the entire file.
 *
 * The counter is computed as: baseCounter + floor(startByte / 16)
 * where baseCounter is the initial counter value from the IV (bytes 8-15).
 *
 * @param ciphertext - Full encrypted data (or at least the block-aligned range covering [startByte, endByte])
 * @param key - 32-byte AES key
 * @param iv - 16-byte counter block (8-byte nonce + 8-byte counter)
 * @param startByte - First byte to decrypt (inclusive, 0-based)
 * @param endByte - Last byte to decrypt (inclusive, 0-based)
 * @returns Decrypted bytes for the requested range
 * @throws CryptoError on invalid inputs or decryption failure
 */
export async function decryptAesCtrRange(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  startByte: number,
  endByte: number
): Promise<Uint8Array> {
  // Validate key size
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError('Decryption failed', 'INVALID_KEY_SIZE');
  }

  // Validate IV size
  if (iv.length !== AES_CTR_IV_SIZE) {
    throw new CryptoError('Decryption failed', 'INVALID_IV_SIZE');
  }

  // Validate range parameters
  if (startByte < 0 || endByte < 0) {
    throw new CryptoError('Decryption failed', 'INVALID_INPUT');
  }
  if (startByte > endByte) {
    throw new CryptoError('Decryption failed', 'INVALID_INPUT');
  }

  // Clamp endByte to actual data
  const clampedEnd = Math.min(endByte, ciphertext.length - 1);
  if (clampedEnd < startByte) {
    // Range is entirely beyond available data
    return new Uint8Array(0);
  }

  try {
    const blockSize = 16;

    // Compute block-aligned range
    const startBlock = Math.floor(startByte / blockSize);
    const endBlock = Math.floor(clampedEnd / blockSize);
    const blockAlignedStart = startBlock * blockSize;
    const blockAlignedEnd = Math.min((endBlock + 1) * blockSize, ciphertext.length);

    // Build counter for starting block:
    // Copy nonce (first 8 bytes of IV), then set counter = baseCounter + startBlock
    const counter = new Uint8Array(16);
    const ivCopy = new Uint8Array(iv);
    counter.set(ivCopy.subarray(0, 8), 0);

    const baseCounter = new DataView(
      ivCopy.buffer,
      ivCopy.byteOffset,
      ivCopy.byteLength
    ).getBigUint64(8, false);
    new DataView(counter.buffer).setBigUint64(8, baseCounter + BigInt(startBlock), false);

    // Copy to ensure proper ArrayBuffer (not SharedArrayBuffer)
    const keyBuffer = new Uint8Array(key).buffer as ArrayBuffer;

    // Import key for decryption
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: AES_CTR_ALGORITHM },
      false,
      ['decrypt']
    );

    // Slice ciphertext to block-aligned range
    const slicedCiphertext = new Uint8Array(ciphertext.slice(blockAlignedStart, blockAlignedEnd))
      .buffer as ArrayBuffer;

    // Decrypt the block-aligned range with computed counter
    const decrypted = await crypto.subtle.decrypt(
      { name: AES_CTR_ALGORITHM, counter, length: AES_CTR_LENGTH },
      cryptoKey,
      slicedCiphertext
    );

    // Extract exact requested bytes from the decrypted block-aligned data
    const offsetInFirstBlock = startByte - blockAlignedStart;
    const requestedLength = clampedEnd - startByte + 1;
    return new Uint8Array(decrypted).slice(
      offsetInFirstBlock,
      offsetInFirstBlock + requestedLength
    );
  } catch (err) {
    if (err instanceof CryptoError) throw err;
    // Generic error to prevent oracle attacks
    throw new CryptoError('Decryption failed', 'DECRYPTION_FAILED');
  }
}
