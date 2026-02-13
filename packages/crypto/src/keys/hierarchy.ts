/**
 * @cipherbox/crypto - Key Hierarchy Functions
 *
 * Functions for deriving and generating keys within the CipherBox hierarchy.
 *
 * Key design decisions (see 03-CONTEXT.md):
 * - Folder keys are randomly generated, then ECIES-wrapped with user's public key
 * - File keys are randomly generated per-file (no deduplication per CRYPT-06)
 * - Context keys are derived deterministically from master keys for specific purposes
 */

import { deriveKey } from './derive';
import { generateFileKey as generateRandomKey } from '../utils/random';

/** Standard salt for CipherBox key derivation */
const CIPHERBOX_SALT = new TextEncoder().encode('CipherBox-v1');

/**
 * Derive a context-specific key from a master key.
 *
 * Uses HKDF-SHA256 with CipherBox-specific salt and the provided context.
 * Same master key + context always produces the same derived key.
 *
 * @param masterKey - 32-byte master key material
 * @param context - Context string for derivation (e.g., 'root-folder', 'ipns-key')
 * @returns 32-byte derived key
 *
 * @example
 * ```typescript
 * const rootKey = await deriveContextKey(vaultMasterKey, 'root-folder');
 * ```
 */
export async function deriveContextKey(
  masterKey: Uint8Array,
  context: string
): Promise<Uint8Array> {
  const info = new TextEncoder().encode(context);

  return deriveKey({
    inputKey: masterKey,
    salt: CIPHERBOX_SALT,
    info,
    outputLength: 32,
  });
}

/**
 * Generate a new random folder key.
 *
 * Folder keys are randomly generated, NOT derived from a hierarchy.
 * They are then ECIES-wrapped with the user's public key for storage.
 *
 * @returns Random 32-byte key suitable for AES-256-GCM
 */
export async function generateFolderKey(): Promise<Uint8Array> {
  return generateRandomKey();
}

/**
 * Generate a new random file key.
 *
 * Each file gets a unique random key (no deduplication per CRYPT-06).
 * This is a security feature - prevents content leakage via key reuse.
 *
 * Re-exported from utils/random for API consistency with generateFolderKey.
 *
 * @returns Random 32-byte key suitable for AES-256-GCM
 */
export { generateFileKey } from '../utils/random';
