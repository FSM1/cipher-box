/**
 * @cipherbox/core - Vault Key Blob v2 Format
 *
 * Binary envelope for storing ECIES-encrypted rootFolderKey on IPFS.
 * This is a key-only blob — folder metadata is stored separately at
 * the root folder's own IPNS name using standard v1 JSON format.
 *
 * Format: 0x02 | uint16_BE(key_len) | encrypted_key
 *
 * This module is pure byte manipulation with zero external dependencies
 * (beyond types), making it easy to verify and port to other languages (Rust).
 *
 * Cross-platform test vectors in vault-blob-vectors.test.ts ensure binary
 * compatibility between TypeScript and Rust implementations.
 */

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
 * Serialize vault key blob v2.
 *
 * Constructs a binary envelope:
 *   byte 0:    version (0x02)
 *   bytes 1-2: key_len as big-endian uint16
 *   bytes 3..: encrypted rootFolderKey (key_len bytes)
 *
 * @param encryptedRootFolderKey - ECIES-wrapped rootFolderKey (typically 129 bytes)
 * @returns Complete v2 key blob ready for IPFS storage
 */
export function serializeVaultBlobV2(encryptedRootFolderKey: Uint8Array): Uint8Array {
  const keyLen = encryptedRootFolderKey.length;
  if (keyLen === 0) {
    throw new Error('Encrypted key must not be empty for v2 blob');
  }
  if (keyLen > 0xffff) {
    throw new Error(`Encrypted key too long for v2 blob (${keyLen} bytes, max ${0xffff})`);
  }
  const result = new Uint8Array(3 + keyLen);

  // Version byte
  result[0] = BLOB_V2_VERSION;
  // Key length as big-endian uint16
  result[1] = (keyLen >> 8) & 0xff;
  result[2] = keyLen & 0xff;
  // ECIES-encrypted rootFolderKey
  result.set(encryptedRootFolderKey, 3);

  return result;
}

/**
 * Deserialize vault key blob v2 to extract the encrypted rootFolderKey.
 *
 * Validates the version byte and key_len field, then slices the key bytes.
 *
 * @param blob - Complete v2 key blob from IPFS
 * @returns The ECIES-encrypted rootFolderKey
 * @throws Error if blob is not v2 format, truncated, or key_len is invalid
 */
export function deserializeVaultBlobV2(blob: Uint8Array): Uint8Array {
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

  return blob.slice(3, 3 + keyLen);
}
