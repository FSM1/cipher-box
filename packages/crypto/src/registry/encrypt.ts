/**
 * @cipherbox/crypto - Device Registry Encryption
 *
 * ECIES encryption/decryption for the device registry blob.
 * Uses the same wrapKey/unwrapKey primitives as folder key wrapping.
 *
 * Note: wrapKey/unwrapKey handle arbitrary-length data (not just 32-byte keys).
 * eciesjs internally uses AES-256-GCM for the symmetric portion, so any
 * length payload works. Overhead is ~97 bytes (65 ephemeral pubkey + 16 nonce + 16 tag).
 * A 10KB registry produces ~10.1KB ciphertext.
 */

import { wrapKey } from '../ecies/encrypt';
import { unwrapKey } from '../ecies/decrypt';
import { validateDeviceRegistry } from './schema';
import { CryptoError } from '../types';
import { clearBytes } from '../utils/memory';
import type { DeviceRegistry } from './types';

/**
 * Encrypt the device registry for IPFS storage.
 *
 * Serializes the registry to JSON and encrypts with ECIES using
 * the user's secp256k1 publicKey. Only the holder of the corresponding
 * privateKey can decrypt it.
 *
 * @param registry - The device registry to encrypt
 * @param userPublicKey - 65-byte uncompressed secp256k1 public key
 * @returns Encrypted registry blob
 */
export async function encryptRegistry(
  registry: DeviceRegistry,
  userPublicKey: Uint8Array
): Promise<Uint8Array> {
  const plaintext = new TextEncoder().encode(JSON.stringify(registry));
  try {
    return await wrapKey(plaintext, userPublicKey);
  } finally {
    clearBytes(plaintext);
  }
}

/**
 * Decrypt the device registry from IPFS storage.
 *
 * Decrypts with ECIES using the user's secp256k1 privateKey,
 * parses the JSON, and validates the schema.
 *
 * @param encrypted - ECIES-encrypted registry blob from IPFS
 * @param userPrivateKey - 32-byte secp256k1 private key
 * @returns Validated DeviceRegistry
 * @throws CryptoError if decryption or validation fails
 */
export async function decryptRegistry(
  encrypted: Uint8Array,
  userPrivateKey: Uint8Array
): Promise<DeviceRegistry> {
  const plaintext = await unwrapKey(encrypted, userPrivateKey);
  try {
    const json = new TextDecoder().decode(plaintext);
    const parsed = JSON.parse(json);
    return validateDeviceRegistry(parsed);
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError('Registry decryption produced invalid data', 'DECRYPTION_FAILED');
  } finally {
    clearBytes(plaintext);
  }
}
