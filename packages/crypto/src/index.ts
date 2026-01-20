/**
 * @cipherbox/crypto
 *
 * Shared cryptographic utilities for CipherBox.
 * Provides AES-256-GCM encryption, ECIES key wrapping, and Ed25519 signing.
 *
 * Security principles:
 * - All operations use Web Crypto API or audited libraries (@noble/*, eciesjs)
 * - Error messages are generic to prevent oracle attacks
 * - Keys are Uint8Array - never convert to/from strings for sensitive data
 *
 * @example
 * ```typescript
 * import {
 *   generateFileKey,
 *   generateIv,
 *   encryptAesGcm,
 *   decryptAesGcm,
 *   wrapKey,
 *   unwrapKey
 * } from '@cipherbox/crypto';
 *
 * // Encrypt file content
 * const fileKey = generateFileKey();
 * const iv = generateIv();
 * const ciphertext = await encryptAesGcm(plaintext, fileKey, iv);
 *
 * // Wrap file key with user's public key
 * const wrappedKey = await wrapKey(fileKey, vaultKey.publicKey);
 *
 * // Unwrap and decrypt
 * const unwrappedKey = await unwrapKey(wrappedKey, vaultKey.privateKey);
 * const decrypted = await decryptAesGcm(ciphertext, unwrappedKey, iv);
 * ```
 */

export const CRYPTO_VERSION = '0.1.0';

// AES-256-GCM symmetric encryption
export { encryptAesGcm, decryptAesGcm } from './aes';

// ECIES secp256k1 key wrapping
export { wrapKey, unwrapKey } from './ecies';

// Ed25519 signing for IPNS
export { generateEd25519Keypair, type Ed25519Keypair } from './ed25519';
export { signEd25519, verifyEd25519 } from './ed25519/sign';

// IPNS record signing utilities
export { signIpnsData, IPNS_SIGNATURE_PREFIX } from './ipns';

// Utility functions (only safe public utilities)
export {
  hexToBytes,
  bytesToHex,
  concatBytes,
  clearBytes,
  clearAll,
  generateRandomBytes,
  generateFileKey,
  generateIv,
} from './utils';

// Types
export { CryptoError, type CryptoErrorCode, type VaultKey, type EncryptedData } from './types';

// Constants
export {
  AES_KEY_SIZE,
  AES_IV_SIZE,
  AES_TAG_SIZE,
  SECP256K1_PUBLIC_KEY_SIZE,
  SECP256K1_PRIVATE_KEY_SIZE,
  AES_GCM_ALGORITHM,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
} from './constants';
