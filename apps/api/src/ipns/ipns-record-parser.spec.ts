import { parseIpnsRecord } from './ipns-record-parser';

/**
 * Helper: encode a varint into a Uint8Array.
 */
function encodeVarint(value: bigint): number[] {
  const bytes: number[] = [];
  let v = value;
  while (v > 0x7fn) {
    bytes.push(Number(v & 0x7fn) | 0x80);
    v >>= 7n;
  }
  bytes.push(Number(v));
  return bytes;
}

/**
 * Helper: encode a protobuf tag (fieldNumber << 3 | wireType).
 */
function encodeTag(fieldNumber: number, wireType: number): number[] {
  return encodeVarint(BigInt((fieldNumber << 3) | wireType));
}

/**
 * Helper: encode a length-delimited field (wire type 2).
 */
function encodeLengthDelimited(fieldNumber: number, data: Uint8Array): number[] {
  return [...encodeTag(fieldNumber, 2), ...encodeVarint(BigInt(data.length)), ...data];
}

/**
 * Helper: encode a varint field (wire type 0).
 */
function encodeVarintField(fieldNumber: number, value: bigint): number[] {
  return [...encodeTag(fieldNumber, 0), ...encodeVarint(value)];
}

/**
 * Build a minimal IPNS record protobuf with Value (field 1) and Sequence (field 5).
 */
function buildIpnsRecord(value: string, sequence: bigint): Uint8Array {
  const valueBytes = new TextEncoder().encode(value);
  return new Uint8Array([
    ...encodeLengthDelimited(1, valueBytes),
    ...encodeVarintField(5, sequence),
  ]);
}

describe('parseIpnsRecord', () => {
  it('should parse a valid IPNS record with Value and Sequence', () => {
    const buf = buildIpnsRecord('/ipfs/QmTest123', 42n);
    const result = parseIpnsRecord(buf);

    expect(result.value).toBe('/ipfs/QmTest123');
    expect(result.sequence).toBe(42n);
  });

  it('should handle sequence = 0', () => {
    const buf = buildIpnsRecord('/ipfs/QmZero', 0n);
    const result = parseIpnsRecord(buf);

    expect(result.value).toBe('/ipfs/QmZero');
    expect(result.sequence).toBe(0n);
  });

  it('should handle large sequence numbers', () => {
    const buf = buildIpnsRecord('/ipfs/QmLarge', 9999999999n);
    const result = parseIpnsRecord(buf);

    expect(result.value).toBe('/ipfs/QmLarge');
    expect(result.sequence).toBe(9999999999n);
  });

  it('should default sequence to 0 when field 5 is absent', () => {
    const valueBytes = new TextEncoder().encode('/ipfs/QmNoSeq');
    const buf = new Uint8Array(encodeLengthDelimited(1, valueBytes));
    const result = parseIpnsRecord(buf);

    expect(result.value).toBe('/ipfs/QmNoSeq');
    expect(result.sequence).toBe(0n);
  });

  it('should skip unknown varint fields', () => {
    const buf = new Uint8Array([
      ...encodeLengthDelimited(1, new TextEncoder().encode('/ipfs/QmSkip')),
      ...encodeVarintField(99, 12345n), // unknown field
      ...encodeVarintField(5, 7n),
    ]);
    const result = parseIpnsRecord(buf);

    expect(result.value).toBe('/ipfs/QmSkip');
    expect(result.sequence).toBe(7n);
  });

  it('should skip unknown length-delimited fields', () => {
    const buf = new Uint8Array([
      ...encodeLengthDelimited(1, new TextEncoder().encode('/ipfs/QmSkipLD')),
      ...encodeLengthDelimited(3, new TextEncoder().encode('ignored-data')),
      ...encodeVarintField(5, 10n),
    ]);
    const result = parseIpnsRecord(buf);

    expect(result.value).toBe('/ipfs/QmSkipLD');
    expect(result.sequence).toBe(10n);
  });

  it('should skip 32-bit fixed fields (wire type 5)', () => {
    const buf = new Uint8Array([
      ...encodeLengthDelimited(1, new TextEncoder().encode('/ipfs/QmFixed32')),
      ...encodeTag(10, 5), // wire type 5 = 32-bit
      0,
      0,
      0,
      0, // 4 bytes of fixed32
      ...encodeVarintField(5, 3n),
    ]);
    const result = parseIpnsRecord(buf);

    expect(result.value).toBe('/ipfs/QmFixed32');
    expect(result.sequence).toBe(3n);
  });

  it('should skip 64-bit fixed fields (wire type 1)', () => {
    const buf = new Uint8Array([
      ...encodeLengthDelimited(1, new TextEncoder().encode('/ipfs/QmFixed64')),
      ...encodeTag(10, 1), // wire type 1 = 64-bit
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0, // 8 bytes of fixed64
      ...encodeVarintField(5, 5n),
    ]);
    const result = parseIpnsRecord(buf);

    expect(result.value).toBe('/ipfs/QmFixed64');
    expect(result.sequence).toBe(5n);
  });

  it('should throw on missing Value field', () => {
    const buf = new Uint8Array(encodeVarintField(5, 1n));

    expect(() => parseIpnsRecord(buf)).toThrow('IPNS record missing Value field');
  });

  it('should throw on empty buffer', () => {
    expect(() => parseIpnsRecord(new Uint8Array(0))).toThrow('IPNS record missing Value field');
  });

  it('should throw on unsupported wire type', () => {
    const buf = new Uint8Array([
      ...encodeLengthDelimited(1, new TextEncoder().encode('/ipfs/QmBad')),
      ...encodeTag(6, 3), // wire type 3 = start group (deprecated/unsupported)
    ]);

    expect(() => parseIpnsRecord(buf)).toThrow('Unsupported wire type 3');
  });

  it('should throw when length-delimited field exceeds buffer', () => {
    const buf = new Uint8Array([
      ...encodeTag(1, 2), // field 1, length-delimited
      100, // claims 100 bytes but buffer is too short
    ]);

    expect(() => parseIpnsRecord(buf)).toThrow('Length-delimited field exceeds buffer');
  });

  it('should throw on truncated varint', () => {
    // A byte with continuation bit set but no following byte
    const buf = new Uint8Array([0x80]);

    expect(() => parseIpnsRecord(buf)).toThrow('Unexpected end of buffer reading varint');
  });

  it('should throw on varint exceeding 64-bit', () => {
    // 10 bytes with continuation bits = >63 bit shift
    const buf = new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80]);

    expect(() => parseIpnsRecord(buf)).toThrow('Varint too long');
  });

  it('should use last occurrence when Value field appears multiple times', () => {
    const buf = new Uint8Array([
      ...encodeLengthDelimited(1, new TextEncoder().encode('/ipfs/QmFirst')),
      ...encodeLengthDelimited(1, new TextEncoder().encode('/ipfs/QmSecond')),
      ...encodeVarintField(5, 1n),
    ]);
    const result = parseIpnsRecord(buf);

    expect(result.value).toBe('/ipfs/QmSecond');
  });

  describe('signature fields (7, 8, 9)', () => {
    /**
     * Build a libp2p-wrapped Ed25519 public key (36 bytes).
     * Format: [0x08, 0x01, 0x12, 0x20, ...32 bytes of Ed25519 pubkey]
     */
    function buildLibp2pEd25519PubKey(rawKey: Uint8Array): Uint8Array {
      return new Uint8Array([0x08, 0x01, 0x12, 0x20, ...rawKey]);
    }

    it('should parse signatureV2 (field 8)', () => {
      const sig = new Uint8Array(64).fill(0xab);
      const buf = new Uint8Array([
        ...encodeLengthDelimited(1, new TextEncoder().encode('/ipfs/QmSig')),
        ...encodeVarintField(5, 1n),
        ...encodeLengthDelimited(8, sig),
      ]);
      const result = parseIpnsRecord(buf);

      expect(result.signatureV2).toEqual(sig);
    });

    it('should parse data (field 9)', () => {
      const data = new Uint8Array([0xc0, 0xc1, 0xc2, 0xc3]);
      const buf = new Uint8Array([
        ...encodeLengthDelimited(1, new TextEncoder().encode('/ipfs/QmData')),
        ...encodeVarintField(5, 2n),
        ...encodeLengthDelimited(9, data),
      ]);
      const result = parseIpnsRecord(buf);

      expect(result.data).toEqual(data);
    });

    it('should extract raw Ed25519 pubKey from libp2p-wrapped field 7', () => {
      const rawKey = new Uint8Array(32).fill(0x42);
      const wrappedKey = buildLibp2pEd25519PubKey(rawKey);
      const buf = new Uint8Array([
        ...encodeLengthDelimited(1, new TextEncoder().encode('/ipfs/QmKey')),
        ...encodeVarintField(5, 3n),
        ...encodeLengthDelimited(7, wrappedKey),
      ]);
      const result = parseIpnsRecord(buf);

      expect(result.pubKey).toEqual(rawKey);
    });

    it('should return undefined pubKey for non-Ed25519 wrapped key', () => {
      // Wrong prefix — not a standard libp2p Ed25519 key
      const badKey = new Uint8Array(36).fill(0xff);
      const buf = new Uint8Array([
        ...encodeLengthDelimited(1, new TextEncoder().encode('/ipfs/QmBadKey')),
        ...encodeVarintField(5, 1n),
        ...encodeLengthDelimited(7, badKey),
      ]);
      const result = parseIpnsRecord(buf);

      expect(result.pubKey).toBeUndefined();
    });

    it('should return undefined pubKey for wrong-length wrapped key', () => {
      // Too short (20 bytes instead of 36)
      const shortKey = new Uint8Array([0x08, 0x01, 0x12, 0x20, ...new Uint8Array(16)]);
      const buf = new Uint8Array([
        ...encodeLengthDelimited(1, new TextEncoder().encode('/ipfs/QmShort')),
        ...encodeVarintField(5, 1n),
        ...encodeLengthDelimited(7, shortKey),
      ]);
      const result = parseIpnsRecord(buf);

      expect(result.pubKey).toBeUndefined();
    });

    it('should parse all signature fields together', () => {
      const rawKey = new Uint8Array(32).fill(0x11);
      const wrappedKey = buildLibp2pEd25519PubKey(rawKey);
      const sig = new Uint8Array(64).fill(0x22);
      const data = new Uint8Array(48).fill(0x33);

      const buf = new Uint8Array([
        ...encodeLengthDelimited(1, new TextEncoder().encode('/ipfs/QmAll')),
        ...encodeVarintField(5, 99n),
        ...encodeLengthDelimited(7, wrappedKey),
        ...encodeLengthDelimited(8, sig),
        ...encodeLengthDelimited(9, data),
      ]);
      const result = parseIpnsRecord(buf);

      expect(result.value).toBe('/ipfs/QmAll');
      expect(result.sequence).toBe(99n);
      expect(result.pubKey).toEqual(rawKey);
      expect(result.signatureV2).toEqual(sig);
      expect(result.data).toEqual(data);
    });

    it('should return undefined for missing signature fields', () => {
      const buf = buildIpnsRecord('/ipfs/QmNoSig', 1n);
      const result = parseIpnsRecord(buf);

      expect(result.signatureV2).toBeUndefined();
      expect(result.data).toBeUndefined();
      expect(result.pubKey).toBeUndefined();
    });
  });
});
