import { describe, expect, it } from 'vitest';
import { parseContactCode } from './contactCode';

describe('parseContactCode', () => {
  it('decodes a pasted code to the bytes the engine verifies', () => {
    expect(parseContactCode('00ff10')).toEqual(new Uint8Array([0x00, 0xff, 0x10]));
  });

  it('tolerates the whitespace a wrapped paste carries', () => {
    expect(parseContactCode('  00ff\n  10\t')).toEqual(new Uint8Array([0x00, 0xff, 0x10]));
  });

  it('accepts a code that was pasted in upper case', () => {
    expect(parseContactCode('00FF10')).toEqual(new Uint8Array([0x00, 0xff, 0x10]));
  });

  it('refuses a paste that is not a code rather than sending the engine junk', () => {
    expect(parseContactCode('')).toBeNull();
    expect(parseContactCode('   ')).toBeNull();
    expect(parseContactCode('00ff1')).toBeNull();
    expect(parseContactCode('hello there')).toBeNull();
  });
});
