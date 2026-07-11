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
 * Canonical 8-4-4-4-12 hyphenated UUID shape (upper or lower hex). Checked against
 * the RAW input before any hyphen-stripping so simple-32-hex and loose-hyphen forms
 * are rejected (SC3, Option A: canonical-only acceptance domain, cross-language
 * parity with Rust's build_node_aad canonical pre-check).
 */
const CANONICAL_UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * Convert a canonical hyphenated UUID string to a 16-byte Uint8Array (raw RFC-4122 bytes).
 *
 * Validates the exact canonical 8-4-4-4-12 hyphenated shape (hex digits case-insensitive,
 * hyphens only at the canonical positions) BEFORE stripping hyphens, then delegates to
 * hexToBytes. The conversion is a hex-field parse — never TextEncoder — producing 16 raw
 * bytes in RFC-4122 field order. This is the canonical UUID→bytes path on the TypeScript
 * side (D-04). Non-canonical forms (simple-32-hex, loose-hyphen, braced, urn:uuid:, etc.)
 * are rejected — this collapses the acceptance domain to match Rust's build_node_aad (SC3).
 *
 * @param uuid - Canonical hyphenated UUID string (e.g. "550e8400-e29b-41d4-a716-446655440000")
 * @returns 16-byte Uint8Array in RFC-4122 field order
 * @throws CryptoError with code 'INVALID_AAD_INPUT' if the UUID is not canonical form
 */
export function uuidToBytes(uuid: string): Uint8Array {
  // The length === 36 guard is load-bearing, not redundant: JS `$` (without the `m` flag)
  // also matches immediately before a trailing "\n", so CANONICAL_UUID_RE alone would ACCEPT
  // "550e8400-e29b-41d4-a716-446655440000\n". Rust's is_canonical_uuid_form rejects it up
  // front (bytes.len() != 36), so without this guard the two languages diverge on a
  // trailing-newline UUID — a cross-language parity + soundness gap (SC3).
  if (uuid.length !== 36 || !CANONICAL_UUID_RE.test(uuid)) {
    throw new CryptoError('Malformed UUID', 'INVALID_AAD_INPUT');
  }
  return hexToBytes(uuid.replace(/-/g, ''));
}

/**
 * Convert a Uint8Array to a base64 string.
 *
 * [SECURITY: MEDIUM-08] Chunk-based encoding to avoid call stack issues with
 * large Uint8Arrays (spread operator has argument limits ~65536). Copied
 * verbatim from packages/core/src/node/encode.ts (uint8ArrayToBase64) — this
 * is the canonical base64 encoder every package boundary re-exports from
 * @cipherbox/crypto.
 *
 * @param bytes - Byte array
 * @returns Base64-encoded string
 */
export function bytesToBase64(bytes: Uint8Array): string {
  const CHUNK_SIZE = 32768;
  let result = '';
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.length));
    result += String.fromCharCode(...chunk);
  }
  return btoa(result);
}

/**
 * Convert a base64 string to a Uint8Array.
 *
 * @param b64 - Base64-encoded string
 * @returns Byte array
 */
export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
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
