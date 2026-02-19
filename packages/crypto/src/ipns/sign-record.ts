/**
 * @cipherbox/crypto - IPNS Record Signing
 *
 * Utilities for signing IPNS records according to IPFS spec.
 * See: https://specs.ipfs.tech/ipns/ipns-record/
 *
 * Note: This module provides the signing primitive. Full IPNS record
 * marshaling (protobuf + CBOR) is handled by the `ipns` npm package
 * in Phase 5. This function signs the raw CBOR data.
 */

import { signEd25519 } from '../ed25519';

/**
 * IPNS signature prefix per IPFS spec.
 * This is "ipns-signature:" as UTF-8 bytes.
 * The prefix is concatenated with CBOR data before signing.
 */
export const IPNS_SIGNATURE_PREFIX = new Uint8Array([
  0x69, // 'i'
  0x70, // 'p'
  0x6e, // 'n'
  0x73, // 's'
  0x2d, // '-'
  0x73, // 's'
  0x69, // 'i'
  0x67, // 'g'
  0x6e, // 'n'
  0x61, // 'a'
  0x74, // 't'
  0x75, // 'u'
  0x72, // 'r'
  0x65, // 'e'
  0x3a, // ':'
]);

/**
 * Signs IPNS record data with Ed25519.
 *
 * Per IPFS IPNS spec, the signature is computed over:
 * "ipns-signature:" + cborData
 *
 * @param cborData - The CBOR-encoded IPNS record data to sign
 * @param privateKey - 32-byte Ed25519 private key
 * @returns 64-byte Ed25519 signature
 * @throws CryptoError if signing fails
 */
export async function signIpnsData(
  cborData: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  // Concatenate prefix with CBOR data
  const dataToSign = new Uint8Array(IPNS_SIGNATURE_PREFIX.length + cborData.length);
  dataToSign.set(IPNS_SIGNATURE_PREFIX, 0);
  dataToSign.set(cborData, IPNS_SIGNATURE_PREFIX.length);

  // Sign with Ed25519
  return signEd25519(dataToSign, privateKey);
}
