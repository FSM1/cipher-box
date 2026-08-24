/** Protobuf field 5 (`sequence`, uint64 varint) of the IPNS entry message. */
const SEQUENCE_FIELD_TAG = (5 << 3) | 0;

/**
 * The smallest byte string `MinimalIpnsSequenceReader` reads a sequence out of:
 * the `sequence` field alone, unsigned and unsealed. It stands in for a record
 * everywhere the API treats records as opaque — the republisher only ever moves
 * and orders these bytes, never verifies them (core owns the real codec).
 */
export function minimalIpnsRecord(sequence: bigint): Buffer {
  const bytes: number[] = [SEQUENCE_FIELD_TAG];
  let remaining = sequence;
  do {
    let byte = Number(remaining & 0x7fn);
    remaining >>= 7n;
    if (remaining > 0n) {
      byte |= 0x80;
    }
    bytes.push(byte);
  } while (remaining > 0n);
  return Buffer.from(bytes);
}
