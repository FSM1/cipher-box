/**
 * @cipherbox/crypto - Device Identity Types
 *
 * Type definitions for per-device Ed25519 keypairs.
 */

/**
 * Ed25519 keypair for device identity, with derived device ID.
 *
 * The device ID is the SHA-256 hash of the public key (hex),
 * providing deterministic, verifiable device identity.
 */
export type DeviceKeypair = {
  /** 32-byte Ed25519 public key */
  publicKey: Uint8Array;
  /** 32-byte Ed25519 private key (seed) */
  privateKey: Uint8Array;
  /** SHA-256 hash of publicKey (hex string, 64 chars) */
  deviceId: string;
};
