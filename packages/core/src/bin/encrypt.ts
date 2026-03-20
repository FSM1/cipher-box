/**
 * @cipherbox/core - Recycle Bin Metadata Encryption
 *
 * ECIES encryption/decryption for the recycle bin metadata blob.
 * Uses the same wrapKey/unwrapKey primitives as folder key wrapping.
 *
 * Note: wrapKey/unwrapKey handle arbitrary-length data (not just 32-byte keys).
 * eciesjs internally uses AES-256-GCM for the symmetric portion, so any
 * length payload works. Overhead is ~97 bytes (65 ephemeral pubkey + 16 nonce + 16 tag).
 */

import { wrapKey, unwrapKey, CryptoError, clearBytes } from '@cipherbox/crypto';
import { validateBinMetadata } from './schema';
import type { RecycleBinMetadata } from './types';

/**
 * Encrypt the recycle bin metadata for IPFS storage.
 *
 * Serializes the metadata to JSON and encrypts with ECIES using
 * the user's secp256k1 publicKey. Only the holder of the corresponding
 * privateKey can decrypt it.
 *
 * @param metadata - The recycle bin metadata to encrypt
 * @param userPublicKey - 65-byte uncompressed secp256k1 public key
 * @returns Encrypted metadata blob
 */
export async function encryptBinMetadata(
  metadata: RecycleBinMetadata,
  userPublicKey: Uint8Array
): Promise<Uint8Array> {
  const plaintext = new TextEncoder().encode(JSON.stringify(metadata));
  try {
    return await wrapKey(plaintext, userPublicKey);
  } finally {
    clearBytes(plaintext);
  }
}

/**
 * Decrypt the recycle bin metadata from IPFS storage.
 *
 * Decrypts with ECIES using the user's secp256k1 privateKey,
 * parses the JSON, and validates the schema.
 *
 * @param encrypted - ECIES-encrypted metadata blob from IPFS
 * @param userPrivateKey - 32-byte secp256k1 private key
 * @returns Validated RecycleBinMetadata
 * @throws CryptoError if decryption or validation fails
 */
export async function decryptBinMetadata(
  encrypted: Uint8Array,
  userPrivateKey: Uint8Array
): Promise<RecycleBinMetadata> {
  const plaintext = await unwrapKey(encrypted, userPrivateKey);
  try {
    const json = new TextDecoder().decode(plaintext);
    const parsed = JSON.parse(json);
    return validateBinMetadata(parsed);
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError('Bin metadata decryption produced invalid data', 'DECRYPTION_FAILED');
  } finally {
    clearBytes(plaintext);
  }
}
