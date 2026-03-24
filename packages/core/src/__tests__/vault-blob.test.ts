/**
 * @cipherbox/core - Vault Key Blob v2 Tests
 *
 * Unit tests for v2 binary key blob serialize/deserialize/detect functions.
 */

import { describe, it, expect } from 'vitest';
import {
  serializeVaultBlobV2,
  deserializeVaultBlobV2,
  detectBlobVersion,
  BLOB_V2_VERSION,
} from '../vault/blob';

describe('Vault Key Blob v2', () => {
  describe('BLOB_V2_VERSION', () => {
    it('should equal 0x02', () => {
      expect(BLOB_V2_VERSION).toBe(0x02);
    });
  });

  describe('serializeVaultBlobV2', () => {
    it('should produce correct binary format with 129-byte key', () => {
      const encryptedKey = new Uint8Array(129);
      encryptedKey.fill(0xaa);

      const blob = serializeVaultBlobV2(encryptedKey);

      // Total: 1 (version) + 2 (key_len) + 129 (key)
      expect(blob.length).toBe(1 + 2 + 129);

      // Version byte
      expect(blob[0]).toBe(0x02);

      // Big-endian uint16 key length: 129 = 0x0081
      expect(blob[1]).toBe(0x00);
      expect(blob[2]).toBe(0x81);

      // Key bytes
      expect(blob.slice(3)).toEqual(encryptedKey);
    });

    it('should handle variable key lengths', () => {
      const encryptedKey = new Uint8Array(81);
      encryptedKey.fill(0xbb);

      const blob = serializeVaultBlobV2(encryptedKey);

      // Total: 1 + 2 + 81 = 84
      expect(blob.length).toBe(84);

      // Big-endian uint16 key length: 81 = 0x0051
      expect(blob[1]).toBe(0x00);
      expect(blob[2]).toBe(0x51);

      // Round-trip
      const parsed = deserializeVaultBlobV2(blob);
      expect(parsed.length).toBe(81);
      expect(parsed).toEqual(encryptedKey);
    });

    it('should throw for empty key', () => {
      expect(() => serializeVaultBlobV2(new Uint8Array(0))).toThrow('must not be empty');
    });
  });

  describe('deserializeVaultBlobV2', () => {
    it('should round-trip serialize then deserialize with identical key', () => {
      const encryptedKey = new Uint8Array(129);
      for (let i = 0; i < 129; i++) encryptedKey[i] = i % 256;

      const blob = serializeVaultBlobV2(encryptedKey);
      const parsed = deserializeVaultBlobV2(blob);

      expect(parsed).toEqual(encryptedKey);
    });

    it('should throw "Not a v2 vault blob" for v1 JSON blobs', () => {
      const v1Blob = new TextEncoder().encode('{"encryptedRootFolderKey":"..."}');
      expect(() => deserializeVaultBlobV2(v1Blob)).toThrow('Not a v2 vault blob');
    });

    it('should throw for blobs too short for header', () => {
      const tinyBlob = new Uint8Array([0x02, 0x00]);
      expect(() => deserializeVaultBlobV2(tinyBlob)).toThrow('too short for v2 header');
    });

    it('should throw when key_len exceeds remaining blob bytes', () => {
      const badBlob = new Uint8Array([0x02, 0x01, 0x00, 0xaa, 0xbb]);
      expect(() => deserializeVaultBlobV2(badBlob)).toThrow('too short for key');
    });

    it('should throw for empty blob', () => {
      expect(() => deserializeVaultBlobV2(new Uint8Array(0))).toThrow();
    });

    it('should throw for blob with wrong version byte', () => {
      const wrongVersion = new Uint8Array([0x03, 0x00, 0x01, 0xaa]);
      expect(() => deserializeVaultBlobV2(wrongVersion)).toThrow('Not a v2 vault blob');
    });

    it('should throw for zero-length key_len', () => {
      const zeroKeyLen = new Uint8Array([0x02, 0x00, 0x00]);
      expect(() => deserializeVaultBlobV2(zeroKeyLen)).toThrow('key length must be > 0');
    });
  });

  describe('detectBlobVersion', () => {
    it('should return 2 for v2 blob starting with 0x02', () => {
      const v2Blob = new Uint8Array([0x02, 0x00, 0x81, ...new Array(129).fill(0)]);
      expect(detectBlobVersion(v2Blob)).toBe(2);
    });

    it('should return 1 for v1 JSON blob starting with 0x7B', () => {
      const v1Blob = new TextEncoder().encode('{"encryptedRootFolderKey":"hex..."}');
      expect(detectBlobVersion(v1Blob)).toBe(1);
    });

    it('should return 1 for unknown format (not 0x02)', () => {
      const unknownBlob = new Uint8Array([0x00, 0x01, 0x02]);
      expect(detectBlobVersion(unknownBlob)).toBe(1);
    });

    it('should return 1 for empty blob', () => {
      expect(detectBlobVersion(new Uint8Array(0))).toBe(1);
    });
  });
});
