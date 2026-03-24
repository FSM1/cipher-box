/**
 * @cipherbox/core - Vault Key Blob v2 Test Vectors
 *
 * Hardcoded test vectors for cross-platform verification.
 * These exact hex values must be replicated in the Rust implementation
 * to guarantee binary compatibility across TypeScript and Rust clients.
 */

import { describe, it, expect } from 'vitest';
import { serializeVaultBlobV2, deserializeVaultBlobV2, BLOB_V2_VERSION } from '../vault/blob';

/**
 * Test Vector 1: Standard 129-byte ECIES key (key-only blob).
 *
 * Key (129 bytes): 0xAA followed by 128 bytes incrementing 0x00..0x7F (128 values).
 *
 * Expected binary layout:
 *   [0]     = 0x02 (version)
 *   [1..2]  = 0x00 0x81 (key_len = 129, big-endian)
 *   [3..131] = key bytes (129 bytes)
 */

// Build the 129-byte test key: 0xAA then 0x00..0x7F (128 bytes)
const TEST_KEY_129 = new Uint8Array(129);
TEST_KEY_129[0] = 0xaa;
for (let i = 0; i < 128; i++) {
  TEST_KEY_129[1 + i] = i;
}

// Pre-computed expected hex for the full blob (key only, no metadata)
const EXPECTED_HEX =
  '02' + // version byte
  '0081' + // key_len = 129
  'aa' + // key[0]
  '000102030405060708090a0b0c0d0e0f' + // key[1..16]
  '101112131415161718191a1b1c1d1e1f' + // key[17..32]
  '202122232425262728292a2b2c2d2e2f' + // key[33..48]
  '303132333435363738393a3b3c3d3e3f' + // key[49..64]
  '404142434445464748494a4b4c4d4e4f' + // key[65..80]
  '505152535455565758595a5b5c5d5e5f' + // key[81..96]
  '606162636465666768696a6b6c6d6e6f' + // key[97..112]
  '707172737475767778797a7b7c7d7e7f'; // key[113..128]

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

describe('Vault Key Blob v2 Test Vectors', () => {
  it('Vector 1: serialize produces exact expected hex output', () => {
    const blob = serializeVaultBlobV2(TEST_KEY_129);
    const blobHex = toHex(blob);

    expect(blobHex).toBe(EXPECTED_HEX);
  });

  it('Vector 1: deserialize from expected hex recovers exact key', () => {
    const blob = fromHex(EXPECTED_HEX);
    const parsed = deserializeVaultBlobV2(blob);

    expect(toHex(parsed)).toBe(toHex(TEST_KEY_129));
  });

  it('Vector 1: round-trip produces byte-identical output', () => {
    const blob1 = serializeVaultBlobV2(TEST_KEY_129);
    const parsed = deserializeVaultBlobV2(blob1);
    const blob2 = serializeVaultBlobV2(parsed);

    expect(toHex(blob2)).toBe(toHex(blob1));
  });

  it('Vector 1: version byte is BLOB_V2_VERSION', () => {
    const blob = fromHex(EXPECTED_HEX);
    expect(blob[0]).toBe(BLOB_V2_VERSION);
  });

  it('Vector 2: minimal blob with 1-byte key', () => {
    const minimalKey = new Uint8Array([0xff]);

    const blob = serializeVaultBlobV2(minimalKey);
    const expectedMinimalHex = '02' + '0001' + 'ff';

    expect(toHex(blob)).toBe(expectedMinimalHex);

    const parsed = deserializeVaultBlobV2(blob);
    expect(parsed).toEqual(minimalKey);
  });
});
