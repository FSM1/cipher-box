/**
 * @cipherbox/crypto - buildNodeAad / uuidToBytes Tests
 *
 * Tests for the AAD builder and UUID-to-bytes helper.
 * These form the TS side of the cross-language KAT for the frozen
 * "cipherbox/node-seal/v1" AAD encoding (ADR 0003).
 */

import { describe, it, expect } from 'vitest';
import {
  buildNodeAad,
  sealAesGcmAad,
  unsealAesGcmAad,
  encryptAesGcmAad,
  decryptAesGcmAad,
} from '../aes';
import { uuidToBytes, bytesToHex, hexToBytes } from '../utils/encoding';
import { generateFileKey, generateIv } from '../utils';
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

  it('throws CryptoError INVALID_AAD_INPUT on a 32-char non-hex string', () => {
    // Stripped form is exactly 32 chars but contains a non-hex 'g' — must
    // fail closed with CryptoError, not leak a plain Error from hexToBytes.
    try {
      uuidToBytes('550e8400-e29b-41d4-a716-44665544000g');
      expect.fail('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(CryptoError);
      expect((e as CryptoError).code).toBe('INVALID_AAD_INPUT');
    }
  });

  it('rejects simple-32-hex (no hyphens) — canonical-only (Option A, SC3)', () => {
    // Previously accepted by the strip-then-check implementation; canonical-only
    // tightening must reject any non-canonical form, even a well-formed 32-hex string.
    try {
      uuidToBytes('550e8400e29b41d4a716446655440000');
      expect.fail('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(CryptoError);
      expect((e as CryptoError).code).toBe('INVALID_AAD_INPUT');
    }
  });

  it('rejects loose-hyphen forms (hyphens at non-canonical positions) — canonical-only (Option A, SC3)', () => {
    for (const loose of [
      '55-0e8400e29b41d4a716446655440000',
      '550e-8400-e29b-41d4-a716-446655440000',
    ]) {
      try {
        uuidToBytes(loose);
        expect.fail(`should have thrown for ${loose}`);
      } catch (e) {
        expect(e).toBeInstanceOf(CryptoError);
        expect((e as CryptoError).code).toBe('INVALID_AAD_INPUT');
      }
    }
  });
});

// ============================================================
// UUID acceptance-domain cross-language oracle (SC3)
// ============================================================
//
// Drives buildNodeAad over every case in tests/vectors/crypto/uuid-acceptance.json
// and asserts the TS side agrees with the shared accept/reject verdict. The Rust
// side (crates/crypto/tests/cross_language.rs) drives the identical oracle so a
// divergent acceptance domain between languages fails on both sides.
describe('UUID acceptance-domain oracle (uuid-acceptance.json, SC3)', () => {
  it('accepts/rejects every case exactly as the shared oracle expects', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const oracle = (await import('../../../../tests/vectors/crypto/uuid-acceptance.json')) as any;
    const cases = oracle.cases as Array<{
      description: string;
      node_id: string;
      expected: 'accept' | 'reject';
    }>;
    const { kind, generation, role } = oracle.fixed_params as {
      kind: number;
      generation: number;
      role: number;
    };

    // Non-vacuous guard: at least 2 accept and 6 reject cases must be present.
    expect(cases.length).toBeGreaterThanOrEqual(8);
    expect(cases.filter((c) => c.expected === 'accept').length).toBeGreaterThanOrEqual(2);
    expect(cases.filter((c) => c.expected === 'reject').length).toBeGreaterThanOrEqual(6);

    for (const c of cases) {
      if (c.expected === 'accept') {
        expect(
          () => buildNodeAad(c.node_id, kind, generation, role),
          `expected accept for: ${c.description} (${JSON.stringify(c.node_id)})`
        ).not.toThrow();
      } else if (c.expected === 'reject') {
        try {
          buildNodeAad(c.node_id, kind, generation, role);
          expect.fail(`expected reject for: ${c.description} (${JSON.stringify(c.node_id)})`);
        } catch (e) {
          expect(e).toBeInstanceOf(CryptoError);
          expect((e as CryptoError).code).toBe('INVALID_AAD_INPUT');
        }
      } else {
        // Guard against a typo'd verdict silently passing as a reject case.
        expect.fail(`unknown expected verdict "${c.expected}" for: ${c.description}`);
      }
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

// ============================================================
// sealAesGcmAad / unsealAesGcmAad — AAD-bound seal primitive
// ============================================================

describe('sealAesGcmAad / unsealAesGcmAad (AAD-bound seal)', () => {
  describe('round-trip', () => {
    it('round-trips with matching key and AAD', async () => {
      const key = generateFileKey();
      const plaintext = new TextEncoder().encode('sealed node metadata');
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x01);
      const sealed = await sealAesGcmAad(plaintext, key, aad);
      const unsealed = await unsealAesGcmAad(sealed, key, aad);
      expect(unsealed).toEqual(plaintext);
    });

    it('sealed output length is IV(12) + plaintext.length + tag(16)', async () => {
      const key = generateFileKey();
      const plaintext = new TextEncoder().encode('test payload');
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x01);
      const sealed = await sealAesGcmAad(plaintext, key, aad);
      expect(sealed.length).toBe(12 + plaintext.length + 16);
    });

    it('two identical-input calls produce different blobs (fresh IV per call)', async () => {
      const key = generateFileKey();
      const plaintext = new TextEncoder().encode('same plaintext');
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x01);
      const sealed1 = await sealAesGcmAad(plaintext, key, aad);
      const sealed2 = await sealAesGcmAad(plaintext, key, aad);
      expect(sealed1).not.toEqual(sealed2);
      // Both should round-trip correctly despite different IVs
      const unsealed1 = await unsealAesGcmAad(sealed1, key, aad);
      const unsealed2 = await unsealAesGcmAad(sealed2, key, aad);
      expect(unsealed1).toEqual(plaintext);
      expect(unsealed2).toEqual(plaintext);
    });
  });

  describe('rejection cases', () => {
    it('rejects blob shorter than 28 bytes (MIN_SEALED_SIZE: IV + tag)', async () => {
      const key = generateFileKey();
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x01);
      const shortBlob = new Uint8Array(27);
      await expect(unsealAesGcmAad(shortBlob, key, aad)).rejects.toThrow();
    });

    it('rejects wrong key', async () => {
      const key1 = generateFileKey();
      const key2 = generateFileKey();
      const plaintext = new TextEncoder().encode('secret');
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x01);
      const sealed = await sealAesGcmAad(plaintext, key1, aad);
      await expect(unsealAesGcmAad(sealed, key2, aad)).rejects.toThrow();
    });

    it('rejects non-32-byte key on seal', async () => {
      const shortKey = new Uint8Array(16);
      const plaintext = new TextEncoder().encode('test');
      const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x01);
      await expect(sealAesGcmAad(plaintext, shortKey, aad)).rejects.toThrow();
    });
  });
});

// ============================================================
// encryptAesGcmAad / decryptAesGcmAad — deterministic (IV as arg)
// ============================================================

describe('encryptAesGcmAad / decryptAesGcmAad (deterministic, IV-as-arg)', () => {
  it('is deterministic: same inputs produce same output', async () => {
    const key = generateFileKey();
    const iv = generateIv();
    const plaintext = new TextEncoder().encode('deterministic payload');
    const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x02);
    const ct1 = await encryptAesGcmAad(plaintext, key, iv, aad);
    const ct2 = await encryptAesGcmAad(plaintext, key, iv, aad);
    expect(ct1).toEqual(ct2);
  });

  it('round-trips via decryptAesGcmAad', async () => {
    const key = generateFileKey();
    const iv = generateIv();
    const plaintext = new TextEncoder().encode('aad-bound round-trip');
    const aad = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x02);
    const ciphertext = await encryptAesGcmAad(plaintext, key, iv, aad);
    const decrypted = await decryptAesGcmAad(ciphertext, key, iv, aad);
    expect(decrypted).toEqual(plaintext);
  });

  it('different AAD produces different ciphertext', async () => {
    const key = generateFileKey();
    const iv = generateIv();
    const plaintext = new TextEncoder().encode('same plaintext');
    const aad1 = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x01);
    const aad2 = buildNodeAad(CANONICAL_UUID, CANONICAL_KIND, CANONICAL_GEN, 0x02);
    const ct1 = await encryptAesGcmAad(plaintext, key, iv, aad1);
    const ct2 = await encryptAesGcmAad(plaintext, key, iv, aad2);
    expect(ct1).not.toEqual(ct2);
  });
});

// KAT: assert buildNodeAad output matches the committed frozen ground truth.
// The import path is relative: src/__tests__/ → ../../../.. → project root.
describe('buildNodeAad cross-language KAT (node-aad.json)', () => {
  it('matches committed aad_vectors for all four role bytes', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const vectors = (await import('../../../../tests/vectors/crypto/node-aad.json')) as any;
    const aadVectors = vectors.aad_vectors as Array<{
      description: string;
      node_id: string;
      kind: number;
      generation: number;
      role: number;
      expected_aad: string;
    }>;

    // Guard: all four role bytes must be present; a bare for-of over a
    // truncated array would pass vacuously and silently drop role coverage.
    expect(aadVectors.length).toBe(4);
    const sortedRoles = [...aadVectors.map((v) => v.role)].sort((a, b) => a - b);
    expect(sortedRoles).toEqual([1, 2, 3, 4]);

    for (const v of aadVectors) {
      const aad = buildNodeAad(v.node_id, v.kind, v.generation, v.role);
      expect(bytesToHex(aad)).toBe(v.expected_aad);
    }
  });
});

// ============================================================
// D-01b: Full-seal KAT — encryptAesGcmAad with fixed IV pins the entire AEAD path
// ============================================================

describe('full-seal KAT (seal_vectors in node-aad.json, D-01b)', () => {
  it('matches committed seal_vectors for encryptAesGcmAad with fixed key/iv', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const vectors = (await import('../../../../tests/vectors/crypto/node-aad.json')) as any;
    const sealVectors = vectors.seal_vectors as Array<{
      description: string;
      node_id: string;
      kind: number;
      generation: number;
      role: number;
      key: string;
      iv: string;
      plaintext: string;
      ciphertext: string;
    }>;

    // Guard: exactly 1 committed seal vector — mirrors the Rust `assert_eq!(seal_vectors.len(), 1)`.
    // Exact count (not >= 1) keeps the cross-language coverage contract symmetric: adding a
    // second vector must be an intentional update on both sides, not a silent TS-side accept.
    expect(sealVectors.length).toBe(1);

    for (const v of sealVectors) {
      const key = hexToBytes(v.key);
      const iv = hexToBytes(v.iv);
      const plaintext = hexToBytes(v.plaintext);
      const aad = buildNodeAad(v.node_id, v.kind, v.generation, v.role);
      // encryptAesGcmAad is deterministic for fixed key/iv — the committed ciphertext
      // is the cross-language ground truth proving AAD flows into the AEAD identically
      const result = await encryptAesGcmAad(plaintext, key, iv, aad);
      expect(bytesToHex(result)).toBe(v.ciphertext);

      // Pin the frozen sealed-blob envelope order [IV(12)][ct+tag] (D-00a). The committed
      // ciphertext above only pins the AEAD output; this asserts the high-level seal envelope
      // is IV-FIRST — a seal/unseal pair that silently switched to `ct||iv` would still pass the
      // round-trip and ciphertext checks, but unsealing this explicitly IV-first composition
      // would fail. Cross-checked byte-for-byte on the Rust side (cross_language.rs).
      const sealedEnvelope = new Uint8Array([...iv, ...result]);
      const opened = await unsealAesGcmAad(sealedEnvelope, key, aad);
      expect(bytesToHex(opened)).toBe(v.plaintext);
    }
  });
});

// ============================================================
// D-02 / CRYPTO-03: Extended transplant-resistance and negative suite
// ============================================================

describe('AAD transplant-resistance and negative suite (D-02, CRYPTO-03)', () => {
  const TRANSPLANT_UUID = '550e8400-e29b-41d4-a716-446655440000';
  const TRANSPLANT_UUID_ALT = '12345678-1234-1234-1234-1234567890ab';
  const TRANSPLANT_KIND = 0x01; // folder
  const TRANSPLANT_GEN = 42;
  const TRANSPLANT_ROLE = 0x01; // body

  it('correct-AAD unseal succeeds (proves rejections below are AAD-specific)', async () => {
    const key = generateFileKey();
    const plaintext = new TextEncoder().encode('transplant-resistance test');
    const aad = buildNodeAad(TRANSPLANT_UUID, TRANSPLANT_KIND, TRANSPLANT_GEN, TRANSPLANT_ROLE);
    const sealed = await sealAesGcmAad(plaintext, key, aad);
    const unsealed = await unsealAesGcmAad(sealed, key, aad);
    expect(unsealed).toEqual(plaintext);
  });

  it('rejects when nodeId differs (AAD transplant: wrong node)', async () => {
    const key = generateFileKey();
    const plaintext = new TextEncoder().encode('transplant-resistance test');
    const aadCorrect = buildNodeAad(
      TRANSPLANT_UUID,
      TRANSPLANT_KIND,
      TRANSPLANT_GEN,
      TRANSPLANT_ROLE
    );
    const aadWrongNode = buildNodeAad(
      TRANSPLANT_UUID_ALT,
      TRANSPLANT_KIND,
      TRANSPLANT_GEN,
      TRANSPLANT_ROLE
    );
    const sealed = await sealAesGcmAad(plaintext, key, aadCorrect);
    await expect(unsealAesGcmAad(sealed, key, aadWrongNode)).rejects.toThrow();
  });

  it('rejects when role differs (AAD transplant: wrong role)', async () => {
    const key = generateFileKey();
    const plaintext = new TextEncoder().encode('transplant-resistance test');
    const aadCorrect = buildNodeAad(
      TRANSPLANT_UUID,
      TRANSPLANT_KIND,
      TRANSPLANT_GEN,
      TRANSPLANT_ROLE
    );
    const aadWrongRole = buildNodeAad(
      TRANSPLANT_UUID,
      TRANSPLANT_KIND,
      TRANSPLANT_GEN,
      0x02 // child-readkey instead of body
    );
    const sealed = await sealAesGcmAad(plaintext, key, aadCorrect);
    await expect(unsealAesGcmAad(sealed, key, aadWrongRole)).rejects.toThrow();
  });

  it('rejects when generation differs (AAD transplant: wrong generation)', async () => {
    const key = generateFileKey();
    const plaintext = new TextEncoder().encode('transplant-resistance test');
    const aadCorrect = buildNodeAad(
      TRANSPLANT_UUID,
      TRANSPLANT_KIND,
      TRANSPLANT_GEN,
      TRANSPLANT_ROLE
    );
    const aadWrongGen = buildNodeAad(
      TRANSPLANT_UUID,
      TRANSPLANT_KIND,
      43, // gen+1
      TRANSPLANT_ROLE
    );
    const sealed = await sealAesGcmAad(plaintext, key, aadCorrect);
    await expect(unsealAesGcmAad(sealed, key, aadWrongGen)).rejects.toThrow();
  });

  it('rejects when kind differs (AAD transplant: wrong kind)', async () => {
    const key = generateFileKey();
    const plaintext = new TextEncoder().encode('transplant-resistance test');
    const aadCorrect = buildNodeAad(
      TRANSPLANT_UUID,
      TRANSPLANT_KIND,
      TRANSPLANT_GEN,
      TRANSPLANT_ROLE
    );
    const aadWrongKind = buildNodeAad(
      TRANSPLANT_UUID,
      0x02, // file instead of folder
      TRANSPLANT_GEN,
      TRANSPLANT_ROLE
    );
    const sealed = await sealAesGcmAad(plaintext, key, aadCorrect);
    await expect(unsealAesGcmAad(sealed, key, aadWrongKind)).rejects.toThrow();
  });

  it('rejects when domain version is forged (v1 -> v2)', async () => {
    const key = generateFileKey();
    const plaintext = new TextEncoder().encode('transplant-resistance test');
    const aadCorrect = buildNodeAad(
      TRANSPLANT_UUID,
      TRANSPLANT_KIND,
      TRANSPLANT_GEN,
      TRANSPLANT_ROLE
    );
    // Forge the domain version byte: byte 21 is '1' (0x31) in "v1" — change to '2' (0x32)
    const forgedDomainAad = new Uint8Array(aadCorrect);
    forgedDomainAad[21] = 0x32; // "node-seal/v2" domain
    const sealed = await sealAesGcmAad(plaintext, key, aadCorrect);
    await expect(unsealAesGcmAad(sealed, key, forgedDomainAad)).rejects.toThrow();
  });

  it('rejects when auth tag is tampered (flipped bit in tag area)', async () => {
    const key = generateFileKey();
    const plaintext = new TextEncoder().encode('transplant-resistance test');
    const aad = buildNodeAad(TRANSPLANT_UUID, TRANSPLANT_KIND, TRANSPLANT_GEN, TRANSPLANT_ROLE);
    const sealed = await sealAesGcmAad(plaintext, key, aad);
    // Flip the last byte of the sealed blob (part of the auth tag)
    const tampered = new Uint8Array(sealed);
    tampered[tampered.length - 1] ^= 0x01;
    await expect(unsealAesGcmAad(tampered, key, aad)).rejects.toThrow();
  });

  it('rejects when blob is truncated below IV + tag minimum (28 bytes)', async () => {
    const key = generateFileKey();
    const aad = buildNodeAad(TRANSPLANT_UUID, TRANSPLANT_KIND, TRANSPLANT_GEN, TRANSPLANT_ROLE);
    const truncated = new Uint8Array(27); // one byte below MIN_SEALED_SIZE
    await expect(unsealAesGcmAad(truncated, key, aad)).rejects.toThrow();
  });
});
