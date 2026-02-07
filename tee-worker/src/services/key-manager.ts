/**
 * Key Manager Service
 *
 * ECIES decryption of IPNS private keys with epoch fallback and re-encryption.
 * - Decrypts IPNS keys encrypted with TEE epoch public key
 * - Supports fallback to previous epoch during grace period
 * - Re-encrypts old-epoch keys with current epoch key
 *
 * SECURITY: Caller is responsible for zeroing returned IPNS private keys after use.
 */

import { decrypt, encrypt } from 'eciesjs';
import { getKeypair, getPublicKey } from './tee-keys.js';

/**
 * Decrypt an ECIES-encrypted IPNS private key using the specified epoch's private key.
 *
 * @param encryptedIpnsKey - ECIES ciphertext containing the IPNS Ed25519 private key
 * @param epoch - The key epoch to use for decryption
 * @returns 32-byte Ed25519 IPNS private key
 * @throws Error if decryption fails (wrong epoch or corrupted data)
 */
export async function decryptIpnsKey(
  encryptedIpnsKey: Uint8Array,
  epoch: number
): Promise<Uint8Array> {
  const keypair = await getKeypair(epoch);
  const ipnsPrivateKey = new Uint8Array(decrypt(keypair.privateKey, encryptedIpnsKey));
  return ipnsPrivateKey;
}

/**
 * Decrypt an IPNS key with fallback from current to previous epoch.
 *
 * Tries the current epoch first. If decryption fails and a previous epoch
 * is provided, tries the previous epoch (grace period support).
 *
 * @param encryptedIpnsKey - ECIES ciphertext
 * @param currentEpoch - Current active epoch number
 * @param previousEpoch - Previous epoch number (null if no grace period active)
 * @returns Object with decrypted key and which epoch succeeded
 * @throws Error if both epochs fail
 */
export async function decryptWithFallback(
  encryptedIpnsKey: Uint8Array,
  currentEpoch: number,
  previousEpoch: number | null
): Promise<{ ipnsPrivateKey: Uint8Array; usedEpoch: number }> {
  // Try current epoch first
  try {
    const ipnsPrivateKey = await decryptIpnsKey(encryptedIpnsKey, currentEpoch);
    return { ipnsPrivateKey, usedEpoch: currentEpoch };
  } catch {
    // Current epoch failed -- try previous if available
  }

  // Try previous epoch (grace period)
  if (previousEpoch !== null) {
    try {
      const ipnsPrivateKey = await decryptIpnsKey(encryptedIpnsKey, previousEpoch);
      return { ipnsPrivateKey, usedEpoch: previousEpoch };
    } catch {
      // Previous epoch also failed
    }
  }

  throw new Error('ECIES decryption failed for all available epochs');
}

/**
 * Re-encrypt an IPNS private key for a target epoch.
 *
 * Used during epoch migration: when a key was decrypted with the previous epoch,
 * it gets re-encrypted with the current epoch's public key so future republishes
 * use the current epoch directly.
 *
 * @param ipnsPrivateKey - Plaintext 32-byte Ed25519 IPNS private key
 * @param targetEpoch - The epoch to encrypt for
 * @returns ECIES ciphertext encrypted with target epoch's public key
 */
export async function reEncryptForEpoch(
  ipnsPrivateKey: Uint8Array,
  targetEpoch: number
): Promise<Uint8Array> {
  const targetPublicKey = await getPublicKey(targetEpoch);
  const reEncrypted = new Uint8Array(encrypt(targetPublicKey, ipnsPrivateKey));
  return reEncrypted;
}
