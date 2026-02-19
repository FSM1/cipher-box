/**
 * @cipherbox/crypto - HKDF Key Derivation
 *
 * HKDF-SHA256 key derivation using Web Crypto API.
 * Used for deriving context-specific keys from master key material.
 */

import { CryptoError } from '../types';
import { AES_KEY_SIZE } from '../constants';

/**
 * Parameters for HKDF key derivation.
 */
export type DeriveKeyParams = {
  /** Input key material (e.g., master key, signature) */
  inputKey: Uint8Array;
  /** Salt for HKDF (domain separation) */
  salt: Uint8Array;
  /** Info/context for HKDF (additional context) */
  info: Uint8Array;
  /** Output length in bytes (defaults to 32) */
  outputLength?: number;
};

/**
 * Derive a key using HKDF-SHA256.
 *
 * @param params - Derivation parameters
 * @returns Derived key bytes
 * @throws CryptoError if derivation fails
 *
 * @example
 * ```typescript
 * const derivedKey = await deriveKey({
 *   inputKey: masterKey,
 *   salt: new TextEncoder().encode('CipherBox-v1'),
 *   info: new TextEncoder().encode('folder-key'),
 *   outputLength: 32
 * });
 * ```
 */
export async function deriveKey(params: DeriveKeyParams): Promise<Uint8Array> {
  const { inputKey, salt, info, outputLength = AES_KEY_SIZE } = params;

  try {
    // Copy Uint8Arrays to ensure we have proper ArrayBuffers (not SharedArrayBuffer)
    // This also handles any potential offset issues from TypedArray subviews
    const inputKeyBuffer = new Uint8Array(inputKey).buffer as ArrayBuffer;
    const saltBuffer = new Uint8Array(salt).buffer as ArrayBuffer;
    const infoBuffer = new Uint8Array(info).buffer as ArrayBuffer;

    // Import input key as raw key material for HKDF
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      inputKeyBuffer,
      'HKDF',
      false, // not extractable
      ['deriveBits']
    );

    // Derive key using HKDF-SHA256
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: saltBuffer,
        info: infoBuffer,
      },
      keyMaterial,
      outputLength * 8 // deriveBits takes length in bits
    );

    return new Uint8Array(derivedBits);
  } catch {
    // Generic error to prevent information leakage
    throw new CryptoError('Key derivation failed', 'ENCRYPTION_FAILED');
  }
}
