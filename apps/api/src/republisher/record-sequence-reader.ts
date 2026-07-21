import { Injectable } from '@nestjs/common';

/**
 * Reads the ordering value the record cache uses to refuse regressions.
 *
 * This is a seam, not the canonical IPNS codec — core owns that (AGENTS.md). It
 * reads ONLY the public `sequence` field an IPNS record exposes for monotonic
 * ordering; it never validates the signature, the EOL, or the sealed payload,
 * and the record stays opaque bytes for the keyless re-PUT. The cache it feeds
 * is non-canonical and on no client resolve path, so the worst case of a missing
 * or misread sequence is a skipped cache update (returns `null`), never a trust
 * decision. A core-backed reader can replace this behind the seam later.
 */
@Injectable()
export abstract class RecordSequenceReader {
  /** The record's sequence for cache ordering; null if it cannot be read. */
  abstract read(record: Buffer): bigint | null;
}

/** Protobuf field 5 (`sequence`, uint64 varint) of the IPNS entry message. */
const SEQUENCE_FIELD_TAG = (5 << 3) | 0;
const MAX_VARINT_BYTES = 10;

/**
 * Minimal reader: scans the top-level protobuf fields for the `sequence` varint,
 * skipping every other field by its wire type. Any structural surprise returns
 * `null` — this must never throw into the walk, and a non-canonical cache
 * tolerates a skipped update.
 */
@Injectable()
export class MinimalIpnsSequenceReader extends RecordSequenceReader {
  read(record: Buffer): bigint | null {
    let offset = 0;
    while (offset < record.length) {
      const tag = this.readVarint(record, offset);
      if (!tag) {
        return null;
      }
      offset = tag.next;
      const wireType = Number(tag.value & 0x7n);

      if (Number(tag.value) === SEQUENCE_FIELD_TAG) {
        const seq = this.readVarint(record, offset);
        return seq ? seq.value : null;
      }

      const skipped = this.skipField(record, offset, wireType);
      if (skipped === null) {
        return null;
      }
      offset = skipped;
    }
    return null;
  }

  private skipField(record: Buffer, offset: number, wireType: number): number | null {
    switch (wireType) {
      case 0: {
        const v = this.readVarint(record, offset);
        return v ? v.next : null;
      }
      case 1:
        return offset + 8 <= record.length ? offset + 8 : null;
      case 2: {
        const len = this.readVarint(record, offset);
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

  private readVarint(record: Buffer, offset: number): { value: bigint; next: number } | null {
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
}
