/**
 * Reads the ordering value the store uses to refuse a rollback.
 *
 * Copied from `apps/api/src/republisher/record-sequence-reader.ts`: this tool is
 * not a workspace member, so it imports nothing from the monorepo. It reads ONLY
 * the public `sequence` field; it never validates the signature, the EOL, or the
 * payload, and the record stays opaque bytes.
 */

/** Protobuf field 5 (`sequence`, uint64 varint) of the IPNS entry message. */
const SEQUENCE_FIELD_TAG = (5 << 3) | 0;
const MAX_VARINT_BYTES = 10;

/** The record's sequence; `null` when it cannot be read. */
export function readSequence(record: Buffer): bigint | null {
  let offset = 0;
  while (offset < record.length) {
    const tag = readVarint(record, offset);
    if (!tag) {
      return null;
    }
    offset = tag.next;
    const wireType = Number(tag.value & 0x7n);

    if (Number(tag.value) === SEQUENCE_FIELD_TAG) {
      const seq = readVarint(record, offset);
      return seq ? seq.value : null;
    }

    const skipped = skipField(record, offset, wireType);
    if (skipped === null) {
      return null;
    }
    offset = skipped;
  }
  return null;
}

function skipField(record: Buffer, offset: number, wireType: number): number | null {
  switch (wireType) {
    case 0: {
      const v = readVarint(record, offset);
      return v ? v.next : null;
    }
    case 1:
      return offset + 8 <= record.length ? offset + 8 : null;
    case 2: {
      const len = readVarint(record, offset);
      if (!len) {
        return null;
      }
      const end = len.next + Number(len.value);
      return end <= record.length ? end : null;
    }
    case 5:
      return offset + 4 <= record.length ? offset + 4 : null;
    default:
      return null;
  }
}

function readVarint(record: Buffer, offset: number): { value: bigint; next: number } | null {
  let value = 0n;
  let shift = 0n;
  let index = offset;
  for (let count = 0; count < MAX_VARINT_BYTES && index < record.length; count += 1) {
    const byte = record[index];
    value |= BigInt(byte & 0x7f) << shift;
    index += 1;
    if ((byte & 0x80) === 0) {
      return { value, next: index };
    }
    shift += 7n;
  }
  return null;
}
