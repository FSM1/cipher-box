/**
 * Lightweight inline IPNS record parser.
 *
 * The IPNS record is a protobuf message.  We only need two fields:
 *   field 1 (Value)    – length-delimited bytes, decoded as UTF-8 string
 *   field 5 (Sequence) – varint, decoded as bigint
 *
 * Wire format reference: https://protobuf.dev/programming-guides/encoding/
 */

export interface ParsedIpnsRecord {
  value: string;
  sequence: bigint;
}

function readVarint(buf: Uint8Array, offset: number): [bigint, number] {
  let result = 0n;
  let shift = 0n;
  let pos = offset;
  while (pos < buf.length) {
    const byte = buf[pos];
    result |= BigInt(byte & 0x7f) << shift;
    pos++;
    if ((byte & 0x80) === 0) return [result, pos];
    shift += 7n;
    if (shift > 63n) throw new Error('Varint too long');
  }
  throw new Error('Unexpected end of buffer reading varint');
}

export function parseIpnsRecord(buf: Uint8Array): ParsedIpnsRecord {
  let value: string | undefined;
  let sequence = 0n;

  let pos = 0;
  while (pos < buf.length) {
    const [tag, nextPos] = readVarint(buf, pos);
    pos = nextPos;
    const fieldNumber = Number(tag >> 3n);
    const wireType = Number(tag & 0x7n);

    if (wireType === 0) {
      // Varint
      const [val, np] = readVarint(buf, pos);
      pos = np;
      if (fieldNumber === 5) sequence = val;
    } else if (wireType === 2) {
      // Length-delimited
      const [len, np] = readVarint(buf, pos);
      pos = np;
      const end = pos + Number(len);
      if (end > buf.length) throw new Error('Length-delimited field exceeds buffer');
      if (fieldNumber === 1) {
        value = new TextDecoder().decode(buf.subarray(pos, end));
      }
      pos = end;
    } else if (wireType === 5) {
      pos += 4; // 32-bit
    } else if (wireType === 1) {
      pos += 8; // 64-bit
    } else {
      throw new Error(`Unsupported wire type ${wireType}`);
    }
  }

  if (value === undefined) {
    throw new Error('IPNS record missing Value field');
  }

  return { value, sequence };
}
