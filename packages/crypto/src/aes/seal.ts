/**
 * @cipherbox/crypto - AES-256-GCM Seal/Unseal
 *
 * Higher-level API that handles IV generation and binding automatically.
 * This prevents IV mismanagement by ensuring IV is always stored with ciphertext.
 *
 * Format: IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)
 */

import { CryptoError } from '../types';
import { AES_KEY_SIZE, AES_IV_SIZE, AES_TAG_SIZE } from '../constants';
import { generateIv } from '../utils/random';
import { concatBytes, uuidToBytes } from '../utils/encoding';
import { encryptAesGcm, encryptAesGcmAad } from './encrypt';
import { decryptAesGcm, decryptAesGcmAad } from './decrypt';

/**
 * Frozen domain prefix for the AAD-bound node seal (D-00, ADR 0003).
 * Computed once at module load; never re-created inside the function body.
 *
 * Layout: "cipherbox/node-seal/v1" (22 UTF-8 bytes) ‖ 0x00 (null separator)
 */
const DOMAIN = new TextEncoder().encode('cipherbox/node-seal/v1');
const NULL_SEP = new Uint8Array([0x00]);

/** Minimum sealed data size: IV + auth tag (no plaintext) */
const MIN_SEALED_SIZE = AES_IV_SIZE + AES_TAG_SIZE;

/**
 * Seal data using AES-256-GCM with automatic IV generation.
 *
 * This is the recommended API for encryption. It automatically:
 * 1. Generates a fresh random IV
 * 2. Encrypts the plaintext
 * 3. Prepends the IV to the ciphertext
 *
 * The returned sealed data can be safely stored - the IV is included.
 *
 * @param plaintext - Data to encrypt
 * @param key - 32-byte AES key
 * @returns Sealed data: IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)
 * @throws CryptoError with generic message on any failure
 */
export async function sealAesGcm(plaintext: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  // Validate key size
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError('Encryption failed', 'INVALID_KEY_SIZE');
  }

  // Generate fresh IV for each seal operation
  const iv = generateIv();

  // Encrypt the plaintext
  const ciphertext = await encryptAesGcm(plaintext, key, iv);

  // Return IV || ciphertext (IV is always first 12 bytes)
  return concatBytes(iv, ciphertext);
}

/**
 * Build the AAD (Additional Authenticated Data) for an AAD-bound node seal.
 *
 * Frozen byte layout per D-00 / ADR 0003:
 *   "cipherbox/node-seal/v1" (22 bytes, UTF-8)
 *   ‖ 0x00  (null separator, 1 byte)
 *   ‖ nodeId (16 bytes, raw RFC-4122 UUID bytes — NOT UTF-8 of the string)
 *   ‖ kind  (1 byte: 0x01 folder / 0x02 file / 0x03 root)
 *   ‖ generation (4 bytes, big-endian u32)
 *   ‖ role  (1 byte: 0x01 body / 0x02 child-readkey / 0x03 content / 0x04 child-writekey)
 *
 * Total: 45 bytes. Fail-closed: any invalid input throws (D-03).
 *
 * @param nodeId - Hyphenated UUID string for the node
 * @param kind - Node kind byte (0x01 folder, 0x02 file, 0x03 root)
 * @param generation - Key generation as a non-negative integer in [0, 2^32-1]
 * @param role - Role byte (0x01..0x04)
 * @returns 45-byte AAD
 * @throws CryptoError with code 'INVALID_AAD_INPUT' on any invalid input
 */
export function buildNodeAad(
  nodeId: string,
  kind: number,
  generation: number,
  role: number
): Uint8Array {
  // D-03: fail-closed validation
  if (!([0x01, 0x02, 0x03] as number[]).includes(kind)) {
    throw new CryptoError('Invalid kind for AAD', 'INVALID_AAD_INPUT');
  }
  if (!([0x01, 0x02, 0x03, 0x04] as number[]).includes(role)) {
    throw new CryptoError('Invalid role for AAD', 'INVALID_AAD_INPUT');
  }
  if (!Number.isInteger(generation) || generation < 0 || generation > 0xffffffff) {
    throw new CryptoError('Invalid generation for AAD', 'INVALID_AAD_INPUT');
  }

  // uuidToBytes throws CryptoError('Malformed UUID', 'INVALID_AAD_INPUT') on bad input
  const nodeIdBytes = uuidToBytes(nodeId);

  // Encode generation as 4-byte big-endian u32
  const genBytes = new Uint8Array(4);
  new DataView(genBytes.buffer).setUint32(0, generation, false);

  return concatBytes(
    DOMAIN,
    NULL_SEP,
    nodeIdBytes,
    new Uint8Array([kind]),
    genBytes,
    new Uint8Array([role])
  );
}

/**
 * Seal data using AES-256-GCM with Additional Authenticated Data (AAD) and automatic IV generation.
 *
 * The AAD (e.g. built via buildNodeAad) is bound into the GCM authentication tag,
 * so the sealed blob can only be unsealed with the exact same key AND AAD. This
 * prevents AAD-transplant attacks where a blob is replayed under a different node identity.
 *
 * Each call mints a fresh random 12-byte IV — never reuses an IV under the same key (D-00a).
 *
 * Blob layout (frozen per D-00a / ADR 0003):
 *   IV (12 bytes) ‖ ciphertext ‖ GCM auth tag (16 bytes)
 *
 * @param plaintext - Data to encrypt
 * @param key - 32-byte AES key
 * @param aad - Additional Authenticated Data (e.g. buildNodeAad output)
 * @returns Sealed blob: IV (12 bytes) ‖ ciphertext ‖ auth tag (16 bytes)
 * @throws CryptoError on any failure
 */
export async function sealAesGcmAad(
  plaintext: Uint8Array,
  key: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> {
  // Validate key size
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError('Encryption failed', 'INVALID_KEY_SIZE');
  }

  // Mint a fresh IV — never accept a caller-supplied IV (D-00a: IV reuse under a fixed key is forbidden)
  const iv = generateIv();

  // Encrypt with AAD bound into the auth tag
  const ciphertext = await encryptAesGcmAad(plaintext, key, iv, aad);

  // Return IV ‖ ciphertext (IV is always the first 12 bytes of the blob)
  return concatBytes(iv, ciphertext);
}

/**
 * Unseal data encrypted with sealAesGcmAad.
 *
 * The AAD must be rebuilt identically to what was used during sealing.
 * Any mismatch (different nodeId, role, generation, kind, or domain version) causes
 * authentication failure and the function throws — preventing AAD-transplant attacks.
 *
 * @param sealed - Sealed blob from sealAesGcmAad: IV (12 bytes) ‖ ciphertext ‖ auth tag (16 bytes)
 * @param key - 32-byte AES key (must match sealing key)
 * @param aad - Additional Authenticated Data (must exactly match sealing AAD)
 * @returns Decrypted plaintext
 * @throws CryptoError on any failure (wrong key, wrong AAD, tampered blob, or blob too short)
 */
export async function unsealAesGcmAad(
  sealed: Uint8Array,
  key: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> {
  // Validate key size
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError('Decryption failed', 'INVALID_KEY_SIZE');
  }

  // Validate minimum sealed data size: IV (12) + auth tag (16) = 28 bytes
  if (sealed.length < MIN_SEALED_SIZE) {
    throw new CryptoError('Decryption failed', 'DECRYPTION_FAILED');
  }

  // Extract IV (first 12 bytes)
  const iv = sealed.slice(0, AES_IV_SIZE);

  // Extract ciphertext (everything after IV; includes the 16-byte auth tag)
  const ciphertext = sealed.slice(AES_IV_SIZE);

  // Decrypt with AAD — throws if AAD or key or tag does not match
  return decryptAesGcmAad(ciphertext, key, iv, aad);
}

/**
 * Unseal data encrypted with sealAesGcm.
 *
 * This is the recommended API for decryption. It automatically:
 * 1. Extracts the IV from the sealed data
 * 2. Decrypts and verifies the ciphertext
 *
 * @param sealed - Sealed data from sealAesGcm
 * @param key - 32-byte AES key (must match encryption key)
 * @returns Decrypted plaintext
 * @throws CryptoError with generic message on any failure
 */
export async function unsealAesGcm(sealed: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  // Validate key size
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError('Decryption failed', 'INVALID_KEY_SIZE');
  }

  // Validate minimum sealed data size (IV + auth tag)
  if (sealed.length < MIN_SEALED_SIZE) {
    throw new CryptoError('Decryption failed', 'DECRYPTION_FAILED');
  }

  // Extract IV (first 12 bytes)
  const iv = sealed.slice(0, AES_IV_SIZE);

  // Extract ciphertext (everything after IV)
  const ciphertext = sealed.slice(AES_IV_SIZE);

  // Decrypt and return plaintext
  return decryptAesGcm(ciphertext, key, iv);
}
