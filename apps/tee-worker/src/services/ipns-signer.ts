/**
 * IPNS Record Signing Service
 *
 * Delegates to @cipherbox/core for IPNS record creation and marshaling.
 * TEE-specific: Uses 48-hour record lifetime (vs 24h default) to provide
 * comfortable margin with 6-hour republish interval.
 */

import { createIpnsRecord, marshalIpnsRecord } from '@cipherbox/core';
import { parseIpnsRecord } from '@cipherbox/crypto';

/** 48-hour IPNS record lifetime for TEE-republished records */
const TEE_RECORD_LIFETIME_MS = 48 * 60 * 60 * 1000;

/**
 * Renew an existing IPNS record by re-signing it with only a later EOL.
 *
 * Parses the marshaled existing record and re-signs the SAME value (CID) and
 * SAME sequenceNumber with a fresh validity window. This is the pure lease-renew
 * primitive: it structurally cannot repoint the CID or increment the sequence
 * because value and sequence come exclusively from the parsed existing record.
 *
 * Security invariants (TEE-01 / TEE-02):
 * - value comes from parseIpnsRecord(marshaledExistingRecord).value only
 * - sequence comes from parseIpnsRecord(marshaledExistingRecord).sequence only
 * - no cid argument, no sequence argument — the relay cannot inject either
 *
 * @param ed25519PrivateKey - 32-byte Ed25519 private key (seed)
 * @param marshaledExistingRecord - Protobuf-encoded IPNS record to renew
 * @param lifetimeMs - New validity window in milliseconds (default: 48 hours)
 * @returns Marshaled (protobuf-encoded) renewed IPNS record bytes
 */
export async function renewIpnsRecord(
  ed25519PrivateKey: Uint8Array,
  marshaledExistingRecord: Uint8Array,
  lifetimeMs: number = TEE_RECORD_LIFETIME_MS
): Promise<Uint8Array> {
  const parsed = await parseIpnsRecord(marshaledExistingRecord);
  const record = await createIpnsRecord(
    ed25519PrivateKey,
    parsed.value,
    parsed.sequence,
    lifetimeMs
  );
  return marshalIpnsRecord(record);
}
