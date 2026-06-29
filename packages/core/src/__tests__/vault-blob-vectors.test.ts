/**
 * @cipherbox/core - Vault Key Blob v3 Test Vectors
 *
 * Cross-platform verification vectors for the v3 two-key binary envelope.
 * The frozen hex in tests/vectors/vault-v3-blob.json is the canonical
 * cross-language fixture — the Phase-69 Rust cross_language.rs asserts
 * the same bytes (D-04, D-05).
 *
 * Keys are synthetic ECIES-output stand-ins (not real ciphertext) that
 * freeze the v3 envelope byte-layout independent of ECIES randomness.
 */

import { describe, it, expect } from 'vitest';
import { serializeVaultBlobV3, deserializeVaultBlobV3, BLOB_V3_VERSION } from '../vault/blob';
import VAULT_V3 from '../../../../tests/vectors/vault-v3-blob.json';

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

describe('Vault Key Blob v3 Test Vectors', () => {
  it('Vector: serialize two 129-byte keys produces exact expected hex output', () => {
    const readKey = fromHex(VAULT_V3.read_key_hex);
    const writeKey = fromHex(VAULT_V3.write_key_hex);

    const blob = serializeVaultBlobV3(readKey, writeKey);
    expect(toHex(blob)).toBe(VAULT_V3.expected_blob_hex);
  });

  it('Vector: deserialize from expected hex recovers exact read and write keys', () => {
    const blob = fromHex(VAULT_V3.expected_blob_hex);
    const { encryptedRootReadKey, encryptedRootWriteKey } = deserializeVaultBlobV3(blob);

    expect(toHex(encryptedRootReadKey)).toBe(VAULT_V3.read_key_hex);
    expect(toHex(encryptedRootWriteKey)).toBe(VAULT_V3.write_key_hex);
  });

  it('Vector: version byte is BLOB_V3_VERSION (0x03)', () => {
    const blob = fromHex(VAULT_V3.expected_blob_hex);
    expect(blob[0]).toBe(BLOB_V3_VERSION);
    expect(BLOB_V3_VERSION).toBe(0x03);
  });

  it('Round-trip: deserialize(serialize(a, b)) returns byte-identical keys', () => {
    const readKey = fromHex(VAULT_V3.read_key_hex);
    const writeKey = fromHex(VAULT_V3.write_key_hex);

    const blob = serializeVaultBlobV3(readKey, writeKey);
    const { encryptedRootReadKey, encryptedRootWriteKey } = deserializeVaultBlobV3(blob);

    expect(toHex(encryptedRootReadKey)).toBe(toHex(readKey));
    expect(toHex(encryptedRootWriteKey)).toBe(toHex(writeKey));
  });

  it('Negative: deserializing a v2-version-byte blob (0x02) throws', () => {
    // Build a blob that starts with 0x02 (old v2 version byte)
    const fakeV2 = new Uint8Array([0x02, 0x00, 0x01, 0xaa]);
    expect(() => deserializeVaultBlobV3(fakeV2)).toThrow();
  });

  it('Negative: truncated blob (too short for v3 header) throws', () => {
    const truncated = new Uint8Array([0x03, 0x00]); // only 2 bytes, need >= 5
    expect(() => deserializeVaultBlobV3(truncated)).toThrow();
  });

  it('Negative: blob truncated — missing write key header throws', () => {
    // Valid v3 header + read key, but no write header
    const readKey = fromHex(VAULT_V3.read_key_hex);
    const partial = new Uint8Array(3 + readKey.length); // missing write u16 + body
    partial[0] = 0x03;
    partial[1] = (readKey.length >> 8) & 0xff;
    partial[2] = readKey.length & 0xff;
    partial.set(readKey, 3);
    expect(() => deserializeVaultBlobV3(partial)).toThrow();
  });

  it('Negative: blob truncated — write key body incomplete throws', () => {
    const readKey = fromHex(VAULT_V3.read_key_hex);
    // Write header says 129 bytes but we only provide 1
    const truncated = new Uint8Array(3 + readKey.length + 2 + 1);
    truncated[0] = 0x03;
    truncated[1] = (readKey.length >> 8) & 0xff;
    truncated[2] = readKey.length & 0xff;
    truncated.set(readKey, 3);
    const writeOffset = 3 + readKey.length;
    truncated[writeOffset] = 0x00;
    truncated[writeOffset + 1] = 0x81; // claims 129 bytes
    truncated[writeOffset + 2] = 0xbb; // only 1 byte
    expect(() => deserializeVaultBlobV3(truncated)).toThrow();
  });

  it('Negative: zero-length read key throws on serialize', () => {
    expect(() => serializeVaultBlobV3(new Uint8Array(0), new Uint8Array(1))).toThrow();
  });

  it('Negative: zero-length write key throws on serialize', () => {
    expect(() => serializeVaultBlobV3(new Uint8Array(1), new Uint8Array(0))).toThrow();
  });

  it('Minimal: 1-byte read key + 1-byte write key round-trips', () => {
    const tiny1 = new Uint8Array([0xaa]);
    const tiny2 = new Uint8Array([0xbb]);
    const blob = serializeVaultBlobV3(tiny1, tiny2);
    // Layout: 03 0001 aa 0001 bb = 7 bytes
    expect(blob.length).toBe(7);
    const { encryptedRootReadKey, encryptedRootWriteKey } = deserializeVaultBlobV3(blob);
    expect(encryptedRootReadKey).toEqual(tiny1);
    expect(encryptedRootWriteKey).toEqual(tiny2);
  });
});
