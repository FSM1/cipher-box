/**
 * Lightweight inline IPNS record parser.
 *
 * The IPNS record is a protobuf message. We extract these fields:
 *   field 1 (Value)       – length-delimited bytes, decoded as UTF-8 string
 *   field 5 (Sequence)    – varint, decoded as bigint
 *   field 7 (PubKey)      – length-delimited, protobuf-wrapped Ed25519 public key
 *   field 8 (SignatureV2) – length-delimited, Ed25519 signature bytes
 *   field 9 (Data)        – length-delimited, CBOR-encoded signed data
 *
 * Signature fields (7/8/9) are returned as an all-or-nothing bundle:
 * if any field is missing or pubKey extraction fails, all are omitted.
 *
 * Wire format reference: https://protobuf.dev/programming-guides/encoding/
 */

export interface ParsedIpnsRecord {
  value: string;
  sequence: bigint;
  /** Ed25519 signature bytes (protobuf field 8) */
  signatureV2?: Uint8Array;
  /** CBOR-encoded record data that was signed (protobuf field 9) */
  data?: Uint8Array;
  /** Raw 32-byte Ed25519 public key extracted from protobuf-wrapped libp2p key (field 7) */
  pubKey?: Uint8Array;
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

/**
 * Extract raw 32-byte Ed25519 public key from a protobuf-wrapped libp2p public key.
 *
 * The libp2p public key protobuf wrapping is:
 *   [0x08, 0x01, 0x12, 0x20, ...32 bytes of Ed25519 pubkey]
 *
 * - 0x08 0x01 = field 1 (KeyType), varint, value 1 (Ed25519)
 * - 0x12 0x20 = field 2 (Data), length-delimited, 32 bytes
 *
 * @returns Raw 32-byte Ed25519 public key, or undefined if format is unexpected
 */
function extractEd25519PubKey(wrappedKey: Uint8Array): Uint8Array | undefined {
  // Standard libp2p Ed25519 public key is 36 bytes: 4-byte protobuf prefix + 32-byte key
  if (
    wrappedKey.length === 36 &&
    wrappedKey[0] === 0x08 &&
    wrappedKey[1] === 0x01 &&
    wrappedKey[2] === 0x12 &&
    wrappedKey[3] === 0x20
  ) {
    return wrappedKey.subarray(4);
  }
  return undefined;
}

export function parseIpnsRecord(buf: Uint8Array): ParsedIpnsRecord {
  let value: string | undefined;
  let sequence = 0n;
  let signatureV2: Uint8Array | undefined;
  let data: Uint8Array | undefined;
  let rawPubKey: Uint8Array | undefined;

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
      } else if (fieldNumber === 7) {
        // pubKey - protobuf-wrapped libp2p public key; extract raw Ed25519 key
        const wrappedKey = buf.slice(pos, end);
        rawPubKey = extractEd25519PubKey(wrappedKey);
      } else if (fieldNumber === 8) {
        // signatureV2 - Ed25519 signature bytes
        signatureV2 = buf.slice(pos, end);
      } else if (fieldNumber === 9) {
        // data - CBOR-encoded record data that was signed
        data = buf.slice(pos, end);
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

  // If signatureV2 and data are present but pubKey extraction failed,
  // drop all signature fields — partial signature data is unverifiable
  const hasCompleteSigData = signatureV2 && data && rawPubKey;
  return {
    value,
    sequence,
    signatureV2: hasCompleteSigData ? signatureV2 : undefined,
    data: hasCompleteSigData ? data : undefined,
    pubKey: hasCompleteSigData ? rawPubKey : undefined,
  };
}
