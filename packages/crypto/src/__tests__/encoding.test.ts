/**
 * @cipherbox/crypto - Base64 Codec Golden Vectors
 *
 * TDD suite for Phase 77 Plan 01 (SC2): hoists the canonical base64 codec
 * (`bytesToBase64` / `base64ToBytes`) into `@cipherbox/crypto`, alongside the
 * existing hex helpers. This suite is the parity oracle every downstream
 * dedup (Plans 77-07/08/09) points back to — it must prove byte-identical
 * output vs. the chunked `uint8ArrayToBase64` implementation this codec is
 * copied from (packages/core/src/node/encode.ts, CHUNK_SIZE = 32768).
 */

import { describe, it, expect } from 'vitest';
import { bytesToBase64, base64ToBytes } from '../utils/encoding';

describe('Base64 Codec — Round-Trip', () => {
  it('round-trips an empty array', () => {
    const bytes = new Uint8Array(0);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });

  it('round-trips a 1-byte array', () => {
    const bytes = new Uint8Array([0x2a]);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });

  it('round-trips a 40000-byte array (crosses the 32768 chunk boundary)', () => {
    const bytes = new Uint8Array(40000);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = i % 256;
    }
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });

  it('round-trips a fixed known byte pattern', () => {
    const bytes = new Uint8Array([0x00, 0x01, 0x02, 0xff, 0x7f, 0x80, 0xde, 0xad, 0xbe, 0xef]);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });
});

describe('Base64 Codec — Known Vector (canonical parity oracle)', () => {
  // Deterministic fixed byte array -> known base64 string.
  const KNOWN_BYTES = new Uint8Array([0x00, 0x01, 0x02, 0xff]);
  const KNOWN_B64 = 'AAEC/w==';

  it('bytesToBase64 matches the known vector', () => {
    expect(bytesToBase64(KNOWN_BYTES)).toBe(KNOWN_B64);
  });

  it('base64ToBytes matches the known vector', () => {
    expect(base64ToBytes(KNOWN_B64)).toEqual(KNOWN_BYTES);
  });
});

describe('Base64 Codec — Output Types', () => {
  it('bytesToBase64 returns a string', () => {
    expect(typeof bytesToBase64(new Uint8Array([1, 2, 3]))).toBe('string');
  });

  it('base64ToBytes returns a Uint8Array', () => {
    expect(base64ToBytes('AQID')).toBeInstanceOf(Uint8Array);
  });
});
