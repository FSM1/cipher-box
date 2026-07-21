import { describe, expect, it } from 'vitest';
import { MinimalIpnsSequenceReader } from './record-sequence-reader';

/** Encode a uint64 as a protobuf varint. */
function varint(value: bigint): Buffer {
  const bytes: number[] = [];
  let v = value;
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) {
      byte |= 0x80;
    }
    bytes.push(byte);
  } while (v > 0n);
  return Buffer.from(bytes);
}

/** A field with a varint payload (wire type 0). */
function varintField(fieldNumber: number, value: bigint): Buffer {
  return Buffer.concat([varint(BigInt((fieldNumber << 3) | 0)), varint(value)]);
}

/** A length-delimited field (wire type 2) — e.g. IPNS `value`/`signature`/`data`. */
function bytesField(fieldNumber: number, payload: Buffer): Buffer {
  return Buffer.concat([
    varint(BigInt((fieldNumber << 3) | 2)),
    varint(BigInt(payload.length)),
    payload,
  ]);
}

describe('MinimalIpnsSequenceReader', () => {
  const reader = new MinimalIpnsSequenceReader();

  it('reads the sequence (field 5) when it is the only field', () => {
    expect(reader.read(varintField(5, 7n))).toBe(7n);
  });

  it('reads the sequence past length-delimited and varint fields', () => {
    // A realistic IPNS entry shape: value(1), signatureV1(2), validityType(3),
    // validity(4), then sequence(5), then ttl(6), pubKey(7), data(9).
    const record = Buffer.concat([
      bytesField(1, Buffer.from('value-cid-bytes')),
      bytesField(2, Buffer.from('sigv1')),
      varintField(3, 0n),
      bytesField(4, Buffer.from('2099-01-01T00:00:00Z')),
      varintField(5, 42n),
      varintField(6, 3600n),
      bytesField(7, Buffer.from('pubkey')),
      bytesField(9, Buffer.from('cbor-data')),
    ]);
    expect(reader.read(record)).toBe(42n);
  });

  it('reads a multi-byte sequence varint', () => {
    expect(reader.read(varintField(5, 300n))).toBe(300n);
    expect(reader.read(varintField(5, 9_000_000_000n))).toBe(9_000_000_000n);
  });

  it('returns null when the sequence field is absent', () => {
    const record = Buffer.concat([bytesField(1, Buffer.from('value')), varintField(6, 1n)]);
    expect(reader.read(record)).toBeNull();
  });

  it('returns null for an empty record', () => {
    expect(reader.read(Buffer.alloc(0))).toBeNull();
  });

  it('returns null for a truncated length-delimited field rather than throwing', () => {
    // field 1 claims 50 bytes of payload but the buffer ends early.
    const record = Buffer.concat([varint(BigInt((1 << 3) | 2)), varint(50n), Buffer.from('short')]);
    expect(reader.read(record)).toBeNull();
  });

  it('returns null for a never-terminating varint rather than throwing', () => {
    // Ten continuation bytes with no terminator.
    const record = Buffer.concat([varint(BigInt((5 << 3) | 0)), Buffer.alloc(11, 0x80)]);
    expect(reader.read(record)).toBeNull();
  });
});
