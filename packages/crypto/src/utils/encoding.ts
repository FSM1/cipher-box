/**
 * @cipherbox/crypto - Encoding Utilities
 *
 * Hex and byte conversion utilities.
 */

import { CryptoError } from '../types';

/**
 * Convert hex string to Uint8Array.
 * Handles optional 0x prefix.
 *
 * @param hex - Hex string (with or without 0x prefix)
 * @returns Byte array
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;

  if (cleanHex.length % 2 !== 0) {
    throw new Error('Invalid hex string: odd length');
  }

  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error('Invalid hex string: non-hex character');
    }
    bytes[i] = byte;
  }

  return bytes;
}

/**
 * Convert Uint8Array to hex string (no prefix).
 *
 * @param bytes - Byte array
 * @returns Hex string without 0x prefix
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert a hyphenated UUID string to a 16-byte Uint8Array (raw RFC-4122 bytes).
 *
 * Strips hyphens and delegates to hexToBytes. The conversion is a hex-field
 * parse — never TextEncoder — producing 16 raw bytes in RFC-4122 field order.
 * This is the canonical UUID→bytes path on the TypeScript side (D-04).
 *
 * @param uuid - Hyphenated UUID string (e.g. "550e8400-e29b-41d4-a716-446655440000")
 * @returns 16-byte Uint8Array in RFC-4122 field order
 * @throws CryptoError with code 'INVALID_AAD_INPUT' if the UUID is malformed
 */
export function uuidToBytes(uuid: string): Uint8Array {
  const clean = uuid.replace(/-/g, '');
  if (!/^[0-9a-fA-F]{32}$/.test(clean)) {
    throw new CryptoError('Malformed UUID', 'INVALID_AAD_INPUT');
  }
  return hexToBytes(clean);
}

/**
 * Concatenate multiple Uint8Arrays into one.
 *
 * @param arrays - Arrays to concatenate
 * @returns Combined array
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}
