/**
 * @cipherbox/crypto - IPNS Name Derivation
 *
 * Derives IPNS name (CIDv1 with libp2p-key codec) from Ed25519 public key.
 */

import { publicKeyFromRaw } from '@libp2p/crypto/keys';
import { peerIdFromPublicKey, peerIdFromCID } from '@libp2p/peer-id';
import { CID } from 'multiformats/cid';
import { base36 } from 'multiformats/bases/base36';
import { CryptoError } from '../types';
import { ED25519_PUBLIC_KEY_SIZE } from '../constants';

/**
 * Derives the IPNS name from an Ed25519 public key.
 *
 * The IPNS name is a CIDv1 with:
 * - libp2p-key multicodec (0x72)
 * - identity multihash containing the protobuf-encoded public key
 *
 * This produces names starting with "k51..." in base36 encoding.
 *
 * @param ed25519PublicKey - 32-byte Ed25519 public key
 * @returns IPNS name string (e.g., "k51qzi5uqu5...")
 * @throws CryptoError if public key is invalid
 */
export async function deriveIpnsName(ed25519PublicKey: Uint8Array): Promise<string> {
  // Validate public key size
  if (ed25519PublicKey.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new CryptoError('Invalid Ed25519 public key size', 'INVALID_PUBLIC_KEY_SIZE');
  }

  try {
    // Convert raw 32-byte public key to libp2p PublicKey object
    const libp2pPublicKey = publicKeyFromRaw(ed25519PublicKey);

    // Create PeerId from the public key
    const peerId = peerIdFromPublicKey(libp2pPublicKey);

    // Return CIDv1 string representation in base36 (k51... format)
    return peerId.toCID().toString(base36);
  } catch (error) {
    // Re-throw CryptoErrors as-is
    if (error instanceof CryptoError) {
      throw error;
    }
    // Wrap other errors
    throw new CryptoError('IPNS name derivation failed', 'SIGNING_FAILED');
  }
}

/**
 * Recovers the raw 32-byte Ed25519 public key from an IPNS name.
 *
 * Inverse of {@link deriveIpnsName}: the `k51...` name is a CIDv1 (libp2p-key
 * codec) whose identity multihash embeds the protobuf-encoded Ed25519 public
 * key, so the name alone is sufficient to recover the verifying key — no
 * out-of-band public key is required. For CipherBox's Ed25519-only IPNS model
 * the name is the authoritative source of the public key (the DB `publicKey`
 * column is only a populated-at-publish cache and may be absent for some rows,
 * e.g. shared-folder records).
 *
 * @param ipnsName - IPNS name string (CIDv1 base36, e.g. "k51qzi5uqu5...")
 * @returns the raw 32-byte Ed25519 public key
 * @throws CryptoError if the name is not a valid Ed25519 IPNS name
 */
export function publicKeyFromIpnsName(ipnsName: string): Uint8Array {
  try {
    // The name is a CIDv1 (libp2p-key codec) whose identity multihash embeds the
    // protobuf-encoded Ed25519 public key. Recover it deterministically — this is
    // the exact inverse of the peerIdFromPublicKey(...).toCID() path above.
    const cid = CID.parse(ipnsName, base36);
    const peerId = peerIdFromCID(cid);
    const raw = peerId.publicKey?.raw;
    if (raw == null || raw.length !== ED25519_PUBLIC_KEY_SIZE) {
      // Non-inline / non-Ed25519 key (e.g. RSA, where the name is a hash not the
      // key itself). CipherBox only uses Ed25519 identity keys.
      throw new CryptoError(
        'IPNS name does not encode an Ed25519 public key',
        'INVALID_PUBLIC_KEY_FORMAT'
      );
    }
    return raw;
  } catch (error) {
    if (error instanceof CryptoError) {
      throw error;
    }
    throw new CryptoError('Invalid IPNS name', 'INVALID_PUBLIC_KEY_FORMAT');
  }
}
