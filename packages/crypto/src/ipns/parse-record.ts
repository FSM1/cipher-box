/**
 * @cipherbox/crypto - IPNS Record Parsing
 *
 * Library-backed extraction of the fields CipherBox needs from a marshalled
 * IPNS record. Replaces a hand-rolled protobuf decoder so the wire format
 * stays in lock-step with record creation (`ipns` package on both sides).
 */

import { unmarshalIPNSRecord, extractPublicKeyFromIPNSRecord } from 'ipns';

export interface ParsedIpnsRecord {
  /** IPNS value, e.g. "/ipfs/<cid>" */
  value: string;
  /** Monotonic sequence number */
  sequence: bigint;
  /** Ed25519 SignatureV2 bytes (protobuf field 8) */
  signatureV2?: Uint8Array;
  /** CBOR-encoded signed data that SignatureV2 covers (protobuf field 9) */
  data?: Uint8Array;
  /**
   * Raw 32-byte Ed25519 public key, when the record embeds it (protobuf field 7).
   * Ed25519 "identity" records usually OMIT it (the name encodes the key), so this
   * is frequently undefined — callers supplement it from trusted cached metadata.
   */
  pubKey?: Uint8Array;
  /**
   * End-of-life (EOL) expiration of the record, as a `Date`. Sourced from the
   * `ipns` package's `unmarshalIPNSRecord().validity` (an RFC3339 string) parsed
   * into a `Date`. Used to enforce the strictly-later-EOL renewal invariant
   * (a renewed record must never hold an equal or earlier EOL — SC3 item 4).
   */
  validity: Date;
}

/**
 * Parse a marshalled IPNS record into the fields CipherBox consumes.
 *
 * @param marshalledRecord - Protobuf-encoded IPNS record bytes
 * @returns Extracted value, sequence, signatureV2, data, and (optional) raw pubKey
 * @throws if the bytes are not a valid IPNS record
 */
export async function parseIpnsRecord(marshalledRecord: Uint8Array): Promise<ParsedIpnsRecord> {
  const record = unmarshalIPNSRecord(marshalledRecord);
  // PublicKey object when the record embeds the key; undefined for identity keys
  // that omit it (returned synchronously, so this can't be `.catch`ed). `.raw`
  // is the 32-byte Ed25519 key.
  let pubKey: Uint8Array | undefined;
  try {
    const publicKey = await extractPublicKeyFromIPNSRecord(record);
    pubKey = publicKey?.raw;
  } catch {
    pubKey = undefined;
  }
  return {
    value: record.value,
    sequence: record.sequence,
    signatureV2: record.signatureV2,
    data: record.data,
    pubKey,
    // `record.validity` is the RFC3339 EOL string computed by unmarshalIPNSRecord();
    // parse it to a Date (no hand-rolled CBOR validity decode).
    validity: new Date(record.validity),
  };
}
