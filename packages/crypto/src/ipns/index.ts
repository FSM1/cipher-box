/**
 * @cipherbox/crypto - IPNS Module
 *
 * IPNS record creation, signing, and marshaling utilities.
 *
 * Core functions:
 * - createIpnsRecord: Create and sign IPNS records
 * - deriveIpnsName: Get IPNS name from Ed25519 public key
 * - marshalIpnsRecord/unmarshalIpnsRecord: Serialize/deserialize records
 * - signIpnsData: Low-level signing primitive
 */

// IPNS record creation using ipns npm package
export { createIpnsRecord, type IPNSRecord } from './create-record';

// IPNS name derivation from Ed25519 public key
export { deriveIpnsName } from './derive-name';

// Record serialization
export { marshalIpnsRecord, unmarshalIpnsRecord } from './marshal';

// Low-level signing primitive (kept for compatibility)
export { signIpnsData, IPNS_SIGNATURE_PREFIX } from './sign-record';
