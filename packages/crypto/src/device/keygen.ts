/**
 * @cipherbox/crypto - Device Keypair Generation
 *
 * Generates Ed25519 keypairs for device identity and derives
 * device IDs from public keys using SHA-256.
 */

import { generateEd25519Keypair } from '../ed25519/keygen';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '../utils/encoding';
import type { DeviceKeypair } from './types';

/**
 * Generate a new Ed25519 keypair for device identity.
 *
 * Each physical device gets a unique keypair, stored persistently
 * in IndexedDB (web) or OS keychain (desktop).
 *
 * @returns Device keypair with 32-byte keys and SHA-256 device ID
 */
export function generateDeviceKeypair(): DeviceKeypair {
  const keypair = generateEd25519Keypair();
  const deviceId = deriveDeviceId(keypair.publicKey);

  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.privateKey,
    deviceId,
  };
}

/**
 * Derive a device ID from an Ed25519 public key.
 *
 * Device ID = SHA-256(publicKey) in hex. Useful when loading
 * an existing keypair from storage and need to compute the ID.
 *
 * @param publicKey - 32-byte Ed25519 public key
 * @returns 64-character hex string (SHA-256 hash)
 */
export function deriveDeviceId(publicKey: Uint8Array): string {
  return bytesToHex(sha256(publicKey));
}
