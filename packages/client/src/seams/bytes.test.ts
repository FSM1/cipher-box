import { describe, expect, it } from 'vitest';

import { fromBase64, fromHex, toBase64, toHex } from './bytes.js';

const ALL_BYTES = Uint8Array.from({ length: 256 }, (_, i) => i);

describe('hex codec', () => {
  it('round-trips every byte value', () => {
    expect(fromHex(toHex(ALL_BYTES))).toEqual(ALL_BYTES);
    expect(toHex(new Uint8Array())).toBe('');
    expect(fromHex('')).toEqual(new Uint8Array());
  });

  it('accepts either case', () => {
    expect(fromHex('AbCdEf')).toEqual(fromHex('abcdef'));
  });

  it('rejects an odd length and any non-hex character', () => {
    expect(() => fromHex('abc')).toThrow(/even length/);
    for (const bad of ['zz', 'g0', '0g', '00 1', '0x00', '00ÿÿ']) {
      expect(() => fromHex(bad), bad).toThrow(/non-hex character/);
    }
  });

  it('parks no copy of its input in the realm-global RegExp statics', () => {
    // A regex-based validator would publish the whole string here, which for the
    // login handoff's hex is the vault's root secret.
    /(sentinel)/.exec('sentinel');
    fromHex('deadbeefdeadbeef');

    expect(RegExp.input).toBe('sentinel');
    expect(RegExp.lastMatch).toBe('sentinel');
  });
});

describe('base64 codec', () => {
  it('round-trips every byte value and every padding length', () => {
    expect(fromBase64(toBase64(ALL_BYTES))).toEqual(ALL_BYTES);
    expect(toBase64(new Uint8Array())).toBe('');
    expect(fromBase64('')).toEqual(new Uint8Array());
    for (const length of [1, 2, 3, 4]) {
      const bytes = ALL_BYTES.subarray(0, length);
      expect(fromBase64(toBase64(bytes)), `${length} bytes`).toEqual(bytes);
    }
  });

  it('emits the API-accepted standard alphabet', () => {
    // The API's PostMessageDto rejects anything outside `[A-Za-z0-9+/]+={0,2}`,
    // so a url-safe variant here would 400 every post.
    expect(toBase64(Uint8Array.of(0xfb, 0xef, 0xff))).toBe('++//');
  });

  it('round-trips a blob past the chunked-encode boundary', () => {
    const large = Uint8Array.from({ length: 0x8000 + 7 }, (_, i) => i & 0xff);
    expect(fromBase64(toBase64(large))).toEqual(large);
  });

  it('rejects a non-base64 string', () => {
    expect(() => fromBase64('!!!!')).toThrow(/not a base64 string/);
  });
});
