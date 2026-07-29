import { describe, expect, it } from 'vitest';

import { fromHex, toHex } from './bytes.js';

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
