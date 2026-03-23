/**
 * @cipherbox/core - Vault Blob v2 Tests
 *
 * Unit tests for v2 binary blob serialize/deserialize/detect functions.
 */

import { describe, it, expect } from 'vitest';
import {
  serializeVaultBlobV2,
  deserializeVaultBlobV2,
  detectBlobVersion,
  BLOB_V2_VERSION,
} from '../vault/blob';

describe('Vault Blob v2', () => {
  describe('BLOB_V2_VERSION', () => {
    it('should equal 0x02', () => {
      expect(BLOB_V2_VERSION).toBe(0x02);
    });
  });

  describe('serializeVaultBlobV2', () => {
    it('should produce correct binary format with 129-byte key', () => {
      // Simulate a 129-byte ECIES-encrypted rootFolderKey
      const encryptedKey = new Uint8Array(129);
      encryptedKey.fill(0xaa);

      const metadataJson = new TextEncoder().encode('{"iv":"abc","data":"def"}');

      const blob = serializeVaultBlobV2(encryptedKey, metadataJson);

      // Total: 1 (version) + 2 (key_len) + 129 (key) + 24 (metadata)
      expect(blob.length).toBe(1 + 2 + 129 + metadataJson.length);

      // Version byte
      expect(blob[0]).toBe(0x02);

      // Big-endian uint16 key length: 129 = 0x0081
      expect(blob[1]).toBe(0x00);
      expect(blob[2]).toBe(0x81);

      // Key bytes
      expect(blob.slice(3, 3 + 129)).toEqual(encryptedKey);

      // Metadata bytes
      expect(blob.slice(3 + 129)).toEqual(metadataJson);
    });

    it('should handle variable key lengths', () => {
      // Minimum ECIES ciphertext might be 81 bytes (33 compressed PK + 16 nonce + 16 tag + 16 ciphertext)
      const encryptedKey = new Uint8Array(81);
      encryptedKey.fill(0xbb);

      const metadataJson = new Uint8Array([0x01, 0x02, 0x03]);

      const blob = serializeVaultBlobV2(encryptedKey, metadataJson);

      // Total: 1 + 2 + 81 + 3 = 87
      expect(blob.length).toBe(87);

      // Big-endian uint16 key length: 81 = 0x0051
      expect(blob[1]).toBe(0x00);
      expect(blob[2]).toBe(0x51);

      // Verify key_len field is read correctly via deserialize
      const parsed = deserializeVaultBlobV2(blob);
      expect(parsed.encryptedRootFolderKey.length).toBe(81);
      expect(parsed.encryptedRootFolderKey).toEqual(encryptedKey);
      expect(parsed.encryptedMetadataJson).toEqual(metadataJson);
    });

    it('should handle empty metadata', () => {
      const encryptedKey = new Uint8Array(129);
      const emptyMetadata = new Uint8Array(0);

      const blob = serializeVaultBlobV2(encryptedKey, emptyMetadata);

      expect(blob.length).toBe(1 + 2 + 129);

      const parsed = deserializeVaultBlobV2(blob);
      expect(parsed.encryptedRootFolderKey.length).toBe(129);
      expect(parsed.encryptedMetadataJson.length).toBe(0);
    });
  });

  describe('deserializeVaultBlobV2', () => {
    it('should round-trip serialize then deserialize with identical components', () => {
      const encryptedKey = new Uint8Array(129);
      for (let i = 0; i < 129; i++) encryptedKey[i] = i % 256;

      const metadataJson = new TextEncoder().encode('{"folders":[],"files":[]}');

      const blob = serializeVaultBlobV2(encryptedKey, metadataJson);
      const parsed = deserializeVaultBlobV2(blob);

      expect(parsed.encryptedRootFolderKey).toEqual(encryptedKey);
      expect(parsed.encryptedMetadataJson).toEqual(metadataJson);
    });

    it('should throw "Not a v2 vault blob" for v1 JSON blobs', () => {
      // v1 blobs start with '{' (0x7B)
      const v1Blob = new TextEncoder().encode('{"encryptedRootFolderKey":"..."}');

      expect(() => deserializeVaultBlobV2(v1Blob)).toThrow('Not a v2 vault blob');
    });

    it('should throw for blobs too short for header', () => {
      // Only 2 bytes -- need at least 3 (version + 2 key_len bytes)
      const tinyBlob = new Uint8Array([0x02, 0x00]);

      expect(() => deserializeVaultBlobV2(tinyBlob)).toThrow('too short for v2 header');
    });

    it('should throw when key_len exceeds remaining blob bytes', () => {
      // Header says key is 256 bytes but blob only has 5 bytes total
      const badBlob = new Uint8Array([0x02, 0x01, 0x00, 0xaa, 0xbb]);
      // key_len = (0x01 << 8) | 0x00 = 256, but remaining = 2 bytes

      expect(() => deserializeVaultBlobV2(badBlob)).toThrow('too short for key');
    });

    it('should throw for empty blob', () => {
      expect(() => deserializeVaultBlobV2(new Uint8Array(0))).toThrow();
    });

    it('should throw for blob with wrong version byte', () => {
      const wrongVersion = new Uint8Array([0x03, 0x00, 0x01, 0xaa]);

      expect(() => deserializeVaultBlobV2(wrongVersion)).toThrow('Not a v2 vault blob');
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
      // Any first byte other than 0x02 is treated as v1 (legacy JSON)
      const unknownBlob = new Uint8Array([0x00, 0x01, 0x02]);
      expect(detectBlobVersion(unknownBlob)).toBe(1);
    });

    it('should return 1 for empty blob', () => {
      expect(detectBlobVersion(new Uint8Array(0))).toBe(1);
    });
  });
});
