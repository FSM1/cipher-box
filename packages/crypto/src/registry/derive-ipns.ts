/**
 * @cipherbox/crypto - Registry IPNS Key Derivation
 *
 * Derives a deterministic Ed25519 IPNS keypair for the device registry
 * from the user's secp256k1 privateKey using HKDF-SHA256.
 *
 * Derivation path:
 *   secp256k1 privateKey (32 bytes)
 *     -> HKDF-SHA256(salt="CipherBox-v1", info="cipherbox-device-registry-ipns-v1")
 *     -> 32-byte Ed25519 seed
 *     -> Ed25519 keypair
 *     -> IPNS name (k51...)
 *
 * This enables any authenticated session with the user's privateKey
 * to discover the registry IPNS name without backend assistance.
 */

import { deriveKey } from '../keys/derive';
import * as ed from '@noble/ed25519';
import { deriveIpnsName } from '../ipns/derive-name';
import { CryptoError } from '../types';
import { SECP256K1_PRIVATE_KEY_SIZE } from '../constants';

const REGISTRY_HKDF_SALT = new TextEncoder().encode('CipherBox-v1');
const REGISTRY_HKDF_INFO = new TextEncoder().encode('cipherbox-device-registry-ipns-v1');

/**
 * Derive the deterministic Ed25519 IPNS keypair for the device registry.
 *
 * Given the same secp256k1 privateKey, this always produces the same
 * IPNS name, enabling discovery from any device.
 *
 * @param userPrivateKey - 32-byte secp256k1 private key
 * @returns Ed25519 keypair and IPNS name for the registry
 * @throws CryptoError if the private key is not 32 bytes
 */
export async function deriveRegistryIpnsKeypair(userPrivateKey: Uint8Array): Promise<{
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  ipnsName: string;
}> {
  // Validate input key length
  if (userPrivateKey.length !== SECP256K1_PRIVATE_KEY_SIZE) {
    throw new CryptoError('Invalid private key size for registry derivation', 'INVALID_KEY_SIZE');
  }

  // 1. HKDF: secp256k1 privateKey -> 32-byte Ed25519 seed
  const ed25519Seed = await deriveKey({
    inputKey: userPrivateKey,
    salt: REGISTRY_HKDF_SALT,
    info: REGISTRY_HKDF_INFO,
    outputLength: 32,
  });

  // 2. Derive Ed25519 public key from seed (deterministic)
  const ed25519PublicKey = ed.getPublicKey(ed25519Seed);

  // 3. Derive IPNS name from Ed25519 public key (k51... format)
  const ipnsName = await deriveIpnsName(ed25519PublicKey);

  return {
    privateKey: ed25519Seed,
    publicKey: ed25519PublicKey,
    ipnsName,
  };
}
