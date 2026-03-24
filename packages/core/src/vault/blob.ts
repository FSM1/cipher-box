/**
 * @cipherbox/core - Vault Blob v2 Format
 *
 * Binary envelope format for storing ECIES-encrypted rootFolderKey alongside
 * AES-GCM encrypted folder metadata in a single IPFS blob.
 *
 * Format: 0x02 | uint16_BE(key_len) | encrypted_key | encrypted_metadata_json
 *
 * This module is pure byte manipulation with zero external dependencies
 * (beyond types), making it easy to verify and port to other languages (Rust).
 *
 * Cross-platform test vectors in vault-blob-vectors.test.ts ensure binary
 * compatibility between TypeScript and Rust implementations.
 */

import type { VaultBlobV2 } from './types';

/** Version byte for vault blob v2 format */
export const BLOB_V2_VERSION = 0x02;

/**
 * Detect whether a vault blob is v1 (JSON) or v2 (binary envelope).
 *
 * v1 blobs start with 0x7B ('{' -- JSON object).
 * v2 blobs start with 0x02 (version byte).
 *
 * Any blob that does not start with 0x02 is treated as v1 for backward
 * compatibility -- this includes malformed blobs, which will fail at
 * the JSON parse stage.
 *
 * @param blob - Raw bytes from IPFS
 * @returns 1 for v1 JSON blobs, 2 for v2 binary blobs
 */
export function detectBlobVersion(blob: Uint8Array): 1 | 2 {
  return blob.length > 0 && blob[0] === BLOB_V2_VERSION ? 2 : 1;
}

/**
 * Serialize vault blob v2.
 *
 * Constructs a binary envelope:
 *   byte 0:    version (0x02)
 *   bytes 1-2: key_len as big-endian uint16
 *   bytes 3..: encrypted rootFolderKey (key_len bytes)
 *   remaining: encrypted metadata JSON
 *
 * @param encryptedRootFolderKey - ECIES-wrapped rootFolderKey (typically 129 bytes)
 * @param encryptedMetadataJson - AES-GCM encrypted folder metadata JSON
 * @returns Complete v2 blob ready for IPFS storage
 */
export function serializeVaultBlobV2(
  encryptedRootFolderKey: Uint8Array,
  encryptedMetadataJson: Uint8Array
): Uint8Array {
  const keyLen = encryptedRootFolderKey.length;
  if (keyLen > 0xffff) {
    throw new Error(`Encrypted key too long for v2 blob (${keyLen} bytes, max ${0xffff})`);
  }
  const totalLen = 3 + keyLen + encryptedMetadataJson.length;
  const result = new Uint8Array(totalLen);

  // Version byte
  result[0] = BLOB_V2_VERSION;
  // Key length as big-endian uint16
  result[1] = (keyLen >> 8) & 0xff;
  result[2] = keyLen & 0xff;
  // ECIES-encrypted rootFolderKey
  result.set(encryptedRootFolderKey, 3);
  // AES-GCM encrypted metadata JSON
  result.set(encryptedMetadataJson, 3 + keyLen);

  return result;
}

/**
 * Deserialize vault blob v2 into its components.
 *
 * Validates the version byte and key_len field, then slices the blob
 * into its two components.
 *
 * @param blob - Complete v2 blob from IPFS
 * @returns Parsed components: encryptedRootFolderKey and encryptedMetadataJson
 * @throws Error if blob is not v2 format, truncated, or key_len overflows
 */
export function deserializeVaultBlobV2(blob: Uint8Array): VaultBlobV2 {
  if (blob.length < 3) {
    throw new Error('Vault blob too short for v2 header (need at least 3 bytes)');
  }

  if (blob[0] !== BLOB_V2_VERSION) {
    throw new Error('Not a v2 vault blob');
  }

  const keyLen = (blob[1] << 8) | blob[2];

  if (keyLen === 0) {
    throw new Error('Invalid v2 blob: encrypted key length must be > 0');
  }

  if (blob.length < 3 + keyLen) {
    throw new Error(
      `Vault blob too short for key (expected ${keyLen} bytes, have ${blob.length - 3})`
    );
  }

  return {
    encryptedRootFolderKey: blob.slice(3, 3 + keyLen),
    encryptedMetadataJson: blob.slice(3 + keyLen),
  };
}
