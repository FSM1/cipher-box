/**
 * @cipherbox/crypto - IPNS Name Derivation
 *
 * Derives IPNS name (CIDv1 with libp2p-key codec) from Ed25519 public key.
 */

import { publicKeyFromRaw } from '@libp2p/crypto/keys';
import { peerIdFromPublicKey } from '@libp2p/peer-id';
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

    // Return CIDv1 string representation (k51... format)
    return peerId.toCID().toString();
  } catch (error) {
    // Re-throw CryptoErrors as-is
    if (error instanceof CryptoError) {
      throw error;
    }
    // Wrap other errors
    throw new CryptoError('IPNS name derivation failed', 'SIGNING_FAILED');
  }
}
