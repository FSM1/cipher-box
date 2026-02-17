/**
 * @cipherbox/crypto - File IPNS Key Derivation
 *
 * Derives a deterministic Ed25519 IPNS keypair for a specific file
 * from the user's secp256k1 privateKey + fileId using HKDF-SHA256.
 *
 * Derivation path:
 *   secp256k1 privateKey (32 bytes)
 *     -> HKDF-SHA256(salt="CipherBox-v1", info="cipherbox-file-ipns-v1:{fileId}")
 *     -> 32-byte Ed25519 seed
 *     -> Ed25519 keypair
 *     -> IPNS name (k51...)
 *
 * Domain separation: The fileId in the HKDF info string ensures each file
 * gets a unique IPNS keypair. Different from vault ("cipherbox-vault-ipns-v1")
 * and registry ("cipherbox-device-registry-ipns-v1") derivation domains.
 */

import { deriveKey } from '../keys/derive';
import * as ed from '@noble/ed25519';
import { deriveIpnsName } from '../ipns/derive-name';
import { CryptoError } from '../types';
import { SECP256K1_PRIVATE_KEY_SIZE } from '../constants';

const FILE_HKDF_SALT = new TextEncoder().encode('CipherBox-v1');

/**
 * Derive a deterministic Ed25519 IPNS keypair for a specific file.
 *
 * Given the same secp256k1 privateKey and fileId, this always produces
 * the same IPNS name, enabling file metadata discovery from any device.
 *
 * @param userPrivateKey - 32-byte secp256k1 private key
 * @param fileId - Unique file identifier (UUID, minimum 10 characters)
 * @returns Ed25519 keypair and IPNS name for the file's metadata record
 * @throws CryptoError if the private key is not 32 bytes or fileId is invalid
 */
export async function deriveFileIpnsKeypair(
  userPrivateKey: Uint8Array,
  fileId: string
): Promise<{
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  ipnsName: string;
}> {
  // Validate input key length
  if (userPrivateKey.length !== SECP256K1_PRIVATE_KEY_SIZE) {
    throw new CryptoError('Invalid private key size for file IPNS derivation', 'INVALID_KEY_SIZE');
  }

  // Validate fileId
  if (!fileId || fileId.length < 10) {
    throw new CryptoError(
      'Invalid fileId: must be a non-empty string of at least 10 characters',
      'ENCRYPTION_FAILED'
    );
  }

  // HKDF info includes fileId for per-file domain separation
  const fileHkdfInfo = new TextEncoder().encode(`cipherbox-file-ipns-v1:${fileId}`);

  // 1. HKDF: secp256k1 privateKey -> 32-byte Ed25519 seed
  const ed25519Seed = await deriveKey({
    inputKey: userPrivateKey,
    salt: FILE_HKDF_SALT,
    info: fileHkdfInfo,
    outputLength: 32,
  });

  // 2. Derive Ed25519 public key from seed (deterministic)
  const ed25519PublicKey = await ed.getPublicKeyAsync(ed25519Seed);

  // 3. Derive IPNS name from Ed25519 public key (k51... format)
  const ipnsName = await deriveIpnsName(ed25519PublicKey);

  return {
    privateKey: ed25519Seed,
    publicKey: ed25519PublicKey,
    ipnsName,
  };
}
