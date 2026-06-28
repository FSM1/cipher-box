/**
 * @cipherbox/crypto - buildNodeAad / uuidToBytes Tests
 *
 * Tests for the AAD builder and UUID-to-bytes helper.
 * These form the TS side of the cross-language KAT for the frozen
 * "cipherbox/node-seal/v1" AAD encoding (ADR 0003).
 */

import { describe, it, expect } from 'vitest';
import { buildNodeAad } from '../aes';
import { uuidToBytes } from '../utils/encoding';
import { CryptoError } from '../types';

const CANONICAL_UUID = '550e8400-e29b-41d4-a716-446655440000';
const CANONICAL_KIND = 0x01; // folder
const CANONICAL_GEN = 42;

describe('uuidToBytes', () => {
  it('converts canonical UUID to 16 raw RFC-4122 bytes', () => {
    const bytes = uuidToBytes(CANONICAL_UUID);
    expect(bytes.length).toBe(16);
    expect(Array.from(bytes)).toEqual([
      0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00,
      0x00,
    ]);
  });

  it('throws CryptoError on a UUID whose stripped form is not 32 hex chars', () => {
    expect(() => uuidToBytes('not-a-uuid')).toThrow(CryptoError);
    expect(() => uuidToBytes('550e8400-e29b-41d4-a716-4466554400')).toThrow(CryptoError); // too short
    expect(() => uuidToBytes('')).toThrow(CryptoError);
  });

  it('throws with INVALID_AAD_INPUT code on malformed UUID', () => {
    try {
      uuidToBytes('bad-uuid');
      expect.fail('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(CryptoError);
      expect((e as CryptoError).code).toBe('INVALID_AAD_INPUT');
    }
  });
});

describe('buildNodeAad', () => {
  describe('canonical output shape', () => {
    it('returns exactly 45 bytes for valid input', () => {
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x01);
      expect(aad.length).toBe(45);
    });

    it('encodes domain bytes 0..21 as UTF-8 cipherbox/node-seal/v1', () => {
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x01);
      const domain = new TextDecoder().decode(aad.slice(0, 22));
      expect(domain).toBe('cipherbox/node-seal/v1');
    });

    it('places null separator at byte 22', () => {
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x01);
      expect(aad[22]).toBe(0x00);
    });

    it('places raw UUID bytes at positions 23..38', () => {
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x01);
      const nodeIdBytes = aad.slice(23, 39);
      expect(Array.from(nodeIdBytes)).toEqual([
        0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00,
        0x00,
      ]);
    });

    it('places kind byte at position 39', () => {
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x01);
      expect(aad[39]).toBe(0x01);
    });

    it('places generation as 4-byte big-endian at bytes 40..43', () => {
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x01);
      expect(Array.from(aad.slice(40, 44))).toEqual([0x00, 0x00, 0x00, 0x2a]);
    });

    it('places role byte at position 44', () => {
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x01);
      expect(aad[44]).toBe(0x01);
    });
  });

  describe('generation edge cases', () => {
    it('encodes generation 0 as four zero bytes', () => {
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, 0, 0x01);
      expect(Array.from(aad.slice(40, 44))).toEqual([0x00, 0x00, 0x00, 0x00]);
    });

    it('encodes generation 0xFFFFFFFF as four 0xff bytes', () => {
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, 0xffffffff, 0x01);
      expect(Array.from(aad.slice(40, 44))).toEqual([0xff, 0xff, 0xff, 0xff]);
    });
  });

  describe('fail-closed validation (D-03)', () => {
    it('throws on kind not in {0x01,0x02,0x03}', () => {
      expect(() => buildNodeAad(CANONICAL_UUID, 0x00, CANONICAL_GEN, 0x01)).toThrow(CryptoError);
      expect(() => buildNodeAad(CANONICAL_UUID, 0x04, CANONICAL_GEN, 0x01)).toThrow(CryptoError);
      expect(() => buildNodeAad(CANONICAL_UUID, 0xff, CANONICAL_GEN, 0x01)).toThrow(CryptoError);
    });

    it('throws with INVALID_AAD_INPUT code on bad kind', () => {
      try {
        buildNodeAad(CANONICAL_UUID, 0x00, CANONICAL_GEN, 0x01);
        expect.fail('should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(CryptoError);
        expect((e as CryptoError).code).toBe('INVALID_AAD_INPUT');
      }
    });

    it('throws on role not in {0x01,0x02,0x03,0x04}', () => {
      expect(() => buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x00)).toThrow(
        CryptoError
      );
      expect(() => buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x05)).toThrow(
        CryptoError
      );
    });

    it('throws with INVALID_AAD_INPUT code on bad role', () => {
      try {
        buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x05);
        expect.fail('should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(CryptoError);
        expect((e as CryptoError).code).toBe('INVALID_AAD_INPUT');
      }
    });

    it('throws on generation < 0', () => {
      expect(() => buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, -1, 0x01)).toThrow(CryptoError);
    });

    it('throws on generation > 0xFFFFFFFF', () => {
      expect(() => buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, 0x100000000, 0x01)).toThrow(
        CryptoError
      );
    });

    it('throws on non-integer generation', () => {
      expect(() => buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, 1.5, 0x01)).toThrow(CryptoError);
    });

    it('throws on malformed UUID', () => {
      expect(() => buildNodeAad('not-a-uuid', CANONICAL_KIND, CANONICAL_GEN, 0x01)).toThrow(
        CryptoError
      );
      expect(() => buildNodeAad('', CANONICAL_KIND, CANONICAL_GEN, 0x01)).toThrow(CryptoError);
    });
  });

  describe('valid kind and role variants', () => {
    it('accepts kind 0x01 (folder)', () => {
      expect(() => buildNodeAad(CANONICAL_UUID, 0x01, CANONICAL_GEN, 0x01)).not.toThrow();
    });

    it('accepts kind 0x02 (file)', () => {
      expect(() => buildNodeAad(CANONICAL_UUID, 0x02, CANONICAL_GEN, 0x01)).not.toThrow();
    });

    it('accepts kind 0x03 (root)', () => {
      expect(() => buildNodeAad(CANONICAL_UUID, 0x03, CANONICAL_GEN, 0x01)).not.toThrow();
    });

    it('accepts all four role bytes', () => {
      for (const role of [0x01, 0x02, 0x03, 0x04]) {
        expect(() =>
          buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, role)
        ).not.toThrow();
        const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, role);
        expect(aad[44]).toBe(role);
      }
    });
  });
});

// KAT assertions are added in Task 2 after node-aad.json is committed.
