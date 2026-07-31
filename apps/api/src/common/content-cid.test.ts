import { describe, expect, it } from 'vitest';
import { contentCidCodec } from './content-cid';

// 59-char strings: 7-char prefix + 52 filler chars from the base32 alphabet.
const FILLER = 'a'.repeat(52);

describe('contentCidCodec', () => {
  it('reads raw off a bafkr4i-prefixed CID', () => {
    expect(contentCidCodec(`bafkr4i${FILLER}`)).toBe('raw');
  });

  it('reads dag-cbor off a bafyr4i-prefixed CID', () => {
    expect(contentCidCodec(`bafyr4i${FILLER}`)).toBe('dag-cbor');
  });

  it('rejects a string one character short of the 59-char CID', () => {
    expect(contentCidCodec(`bafkr4i${FILLER.slice(0, -1)}`)).toBeUndefined();
  });

  it('rejects a string one character over the 59-char CID', () => {
    expect(contentCidCodec(`bafkr4i${FILLER}a`)).toBeUndefined();
  });

  it('rejects non-base32 characters (0, 1, 8, 9 are excluded from the alphabet)', () => {
    expect(contentCidCodec(`bafkr4i0${FILLER.slice(1)}`)).toBeUndefined();
    expect(contentCidCodec(`bafkr4i1${FILLER.slice(1)}`)).toBeUndefined();
    expect(contentCidCodec(`bafkr4i8${FILLER.slice(1)}`)).toBeUndefined();
    expect(contentCidCodec(`bafkr4i9${FILLER.slice(1)}`)).toBeUndefined();
  });

  it('rejects uppercase characters (multibase base32 here is lowercase-only)', () => {
    expect(contentCidCodec(`bafkr4iA${FILLER.slice(1)}`)).toBeUndefined();
  });

  it('rejects a string missing the leading b multibase tag', () => {
    expect(contentCidCodec(`xafkr4i${FILLER}`)).toBeUndefined();
  });

  it('rejects a well-formed but unknown prefix', () => {
    expect(contentCidCodec(`bafkr4j${FILLER}`)).toBeUndefined();
  });
});
