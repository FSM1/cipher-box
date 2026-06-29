/**
 * @cipherbox/core - Vault Key Blob v3 Format
 *
 * Binary envelope for storing two ECIES-encrypted root keys on IPFS.
 * Carries both rootReadKey and rootWriteKey in a single blob (NODE-06, D-05).
 *
 * Format: 0x03 | u16_BE(readLen) | ECIES(rootReadKey) | u16_BE(writeLen) | ECIES(rootWriteKey)
 *
 * This module is pure byte manipulation with zero external dependencies
 * (beyond types), making it easy to verify and port to other languages (Rust).
 *
 * Cross-platform test vectors in tests/vectors/vault-v3-blob.json ensure
 * binary compatibility between TypeScript and Rust implementations (D-04).
 */

/** Version byte for vault blob v3 format */
export const BLOB_V3_VERSION = 0x03;

/**
 * Serialize vault key blob v3.
 *
 * Constructs a binary envelope:
 *   byte 0:        version (0x03)
 *   bytes 1-2:     readLen as big-endian uint16
 *   bytes 3..N:    ECIES(rootReadKey)  (readLen bytes)
 *   bytes N+1..2:  writeLen as big-endian uint16
 *   bytes N+3..:   ECIES(rootWriteKey) (writeLen bytes)
 *
 * @param encryptedRootReadKey  - ECIES-wrapped rootReadKey (typically 129 bytes)
 * @param encryptedRootWriteKey - ECIES-wrapped rootWriteKey (typically 129 bytes)
 * @returns Complete v3 key blob ready for IPFS storage
 */
export function serializeVaultBlobV3(
  encryptedRootReadKey: Uint8Array,
  encryptedRootWriteKey: Uint8Array
): Uint8Array {
  const readLen = encryptedRootReadKey.length;
  const writeLen = encryptedRootWriteKey.length;

  if (readLen === 0) {
    throw new Error('Encrypted read key must not be empty for v3 blob');
  }
  if (readLen > 0xffff) {
    throw new Error(`Encrypted read key too long for v3 blob (${readLen} bytes, max ${0xffff})`);
  }
  if (writeLen === 0) {
    throw new Error('Encrypted write key must not be empty for v3 blob');
  }
  if (writeLen > 0xffff) {
    throw new Error(`Encrypted write key too long for v3 blob (${writeLen} bytes, max ${0xffff})`);
  }

  // Layout: 0x03 | u16_BE(readLen) | ecies(readKey) | u16_BE(writeLen) | ecies(writeKey)
  const result = new Uint8Array(1 + 2 + readLen + 2 + writeLen);

  // Version byte
  result[0] = BLOB_V3_VERSION;

  // Read key length as big-endian uint16
  result[1] = (readLen >> 8) & 0xff;
  result[2] = readLen & 0xff;

  // ECIES-encrypted rootReadKey
  result.set(encryptedRootReadKey, 3);

  // Write key length as big-endian uint16
  const writeOffset = 3 + readLen;
  result[writeOffset] = (writeLen >> 8) & 0xff;
  result[writeOffset + 1] = writeLen & 0xff;

  // ECIES-encrypted rootWriteKey
  result.set(encryptedRootWriteKey, writeOffset + 2);

  return result;
}

/**
 * Deserialize vault key blob v3 to extract both encrypted root keys.
 *
 * Validates the version byte, length fields, and bounds of the write
 * key segment before returning.
 *
 * @param blob - Complete v3 key blob from IPFS
 * @returns { encryptedRootReadKey, encryptedRootWriteKey } as subarray views
 * @throws Error if blob is not v3 format, truncated, or length fields are invalid
 */
export function deserializeVaultBlobV3(blob: Uint8Array): {
  encryptedRootReadKey: Uint8Array;
  encryptedRootWriteKey: Uint8Array;
} {
  if (blob.length < 5) {
    throw new Error('Vault blob too short for v3 header (need at least 5 bytes)');
  }

  if (blob[0] !== BLOB_V3_VERSION) {
    throw new Error('Not a v3 vault blob');
  }

  const readLen = (blob[1] << 8) | blob[2];

  if (readLen === 0) {
    throw new Error('Invalid v3 blob: read key length must be > 0');
  }

  if (blob.length < 3 + readLen + 2) {
    throw new Error('Vault blob truncated (missing write key header)');
  }

  // slice (copy), not subarray (view): EncryptedVaultKeys is a storable struct, so
  // the returned keys must own their buffers and not alias the caller's blob — a
  // later zeroization of the source blob (D-09) must not corrupt cached keys.
  const encryptedRootReadKey = blob.slice(3, 3 + readLen);

  const writeOffset = 3 + readLen;
  const writeLen = (blob[writeOffset] << 8) | blob[writeOffset + 1];

  if (writeLen === 0) {
    throw new Error('Invalid v3 blob: write key length must be > 0');
  }

  if (blob.length < writeOffset + 2 + writeLen) {
    throw new Error('Vault blob truncated (write key)');
  }

  const encryptedRootWriteKey = blob.slice(writeOffset + 2, writeOffset + 2 + writeLen);

  return { encryptedRootReadKey, encryptedRootWriteKey };
}
