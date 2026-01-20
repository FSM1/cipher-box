/**
 * @cipherbox/crypto - Constants
 *
 * Cryptographic parameters and sizes.
 */

/** AES-256-GCM key size in bytes (256 bits) */
export const AES_KEY_SIZE = 32;

/** AES-GCM IV size in bytes (96 bits) - optimal for GCM mode */
export const AES_IV_SIZE = 12;

/** AES-GCM authentication tag size in bytes (128 bits) */
export const AES_TAG_SIZE = 16;

/** secp256k1 uncompressed public key size in bytes (04 prefix + x + y coordinates) */
export const SECP256K1_PUBLIC_KEY_SIZE = 65;

/** secp256k1 private key size in bytes */
export const SECP256K1_PRIVATE_KEY_SIZE = 32;

/** AES-GCM algorithm name for Web Crypto API */
export const AES_GCM_ALGORITHM = 'AES-GCM';

/** Ed25519 public key size in bytes */
export const ED25519_PUBLIC_KEY_SIZE = 32;

/** Ed25519 private key size in bytes */
export const ED25519_PRIVATE_KEY_SIZE = 32;

/** Ed25519 signature size in bytes */
export const ED25519_SIGNATURE_SIZE = 64;
