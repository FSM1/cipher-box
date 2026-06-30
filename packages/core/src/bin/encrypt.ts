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

import {
  wrapKey,
  unwrapKey,
  CryptoError,
  clearBytes,
  bytesToHex,
  hexToBytes,
} from '@cipherbox/crypto';
import { validateBinMetadata } from './schema';
import type { RecycleBinMetadata } from './types';

/**
 * Convert in-memory metadata to its JSON wire form: each entry's `nodeReadKey`
 * (a 32-byte `Uint8Array`) is hex-encoded. A `Uint8Array` does NOT survive
 * `JSON.stringify` — it serialises to `{"0":..,"1":..}` — so without this the
 * key is corrupted on the wire and `restoreFromBin` throws at `sealChildReadKey`.
 * See `BinEntry.nodeReadKey`'s "Wire encoding: hex string" contract.
 */
function toBinWireForm(metadata: RecycleBinMetadata): unknown {
  return {
    ...metadata,
    entries: metadata.entries.map((entry) =>
      entry.nodeReadKey instanceof Uint8Array
        ? { ...entry, nodeReadKey: bytesToHex(entry.nodeReadKey) }
        : entry
    ),
  };
}

/**
 * Inverse of {@link toBinWireForm}: rehydrate each entry's hex-string
 * `nodeReadKey` back into a `Uint8Array` after `JSON.parse`, so `restoreFromBin`
 * receives the raw key its type promises. Invalid hex fails closed (the caller
 * wraps this in the decrypt try/catch → `DECRYPTION_FAILED`).
 */
function fromBinWireForm(metadata: RecycleBinMetadata): RecycleBinMetadata {
  return {
    ...metadata,
    entries: metadata.entries.map((entry) => {
      const wire = entry.nodeReadKey as unknown;
      if (typeof wire !== 'string') return entry;
      const decoded = hexToBytes(wire);
      // Fail closed: a valid-hex but wrong-length value must not reach sealChildReadKey.
      if (decoded.length !== 32) {
        throw new CryptoError('Bin metadata nodeReadKey must be 32 bytes', 'DECRYPTION_FAILED');
      }
      return { ...entry, nodeReadKey: decoded };
    }),
  };
}

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
  const plaintext = new TextEncoder().encode(JSON.stringify(toBinWireForm(metadata)));
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
    return fromBinWireForm(validateBinMetadata(parsed));
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError('Bin metadata decryption produced invalid data', 'DECRYPTION_FAILED');
  } finally {
    clearBytes(plaintext);
  }
}
