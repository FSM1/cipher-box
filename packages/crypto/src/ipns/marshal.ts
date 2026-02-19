/**
 * @cipherbox/crypto - IPNS Record Marshaling
 *
 * Wrappers around ipns package serialization functions.
 */

import {
  marshalIPNSRecord as ipnsMarshal,
  unmarshalIPNSRecord as ipnsUnmarshal,
  type IPNSRecord,
} from 'ipns';

/**
 * Serializes an IPNS record to bytes for transmission.
 *
 * The marshaled format is protobuf-encoded and compatible with:
 * - Delegated Routing API (PUT /routing/v1/ipns/{name})
 * - IPFS DHT storage
 * - Kubo RPC API
 *
 * @param record - IPNS record object to serialize
 * @returns Protobuf-encoded bytes
 */
export function marshalIpnsRecord(record: IPNSRecord): Uint8Array {
  return ipnsMarshal(record);
}

/**
 * Deserializes an IPNS record from bytes.
 *
 * @param bytes - Protobuf-encoded IPNS record
 * @returns Parsed IPNS record object
 * @throws Error if bytes are not a valid IPNS record
 */
export function unmarshalIpnsRecord(bytes: Uint8Array): IPNSRecord {
  return ipnsUnmarshal(bytes);
}

// Re-export type for consumers
export type { IPNSRecord };
