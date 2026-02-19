/**
 * @cipherbox/crypto
 *
 * Shared cryptographic utilities for CipherBox.
 * Provides AES-256-GCM encryption, ECIES key wrapping, Ed25519 signing,
 * vault initialization, and key hierarchy management.
 *
 * Security principles:
 * - All operations use Web Crypto API or audited libraries (@noble/*, eciesjs)
 * - Error messages are generic to prevent oracle attacks
 * - Keys are Uint8Array - never convert to/from strings for sensitive data
 * - Private keys exist in memory only - never persisted to storage
 *
 * @example
 * ```typescript
 * import {
 *   initializeVault,
 *   encryptVaultKeys,
 *   decryptVaultKeys,
 *   generateFileKey,
 *   generateIv,
 *   encryptAesGcm,
 *   decryptAesGcm,
 *   wrapKey,
 *   unwrapKey
 * } from '@cipherbox/crypto';
 *
 * // Initialize vault on first sign-in
 * const vault = await initializeVault();
 * const encrypted = await encryptVaultKeys(vault, userPublicKey);
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

export const CRYPTO_VERSION = '0.2.0';

// Vault initialization and key management
export {
  initializeVault,
  encryptVaultKeys,
  decryptVaultKeys,
  deriveVaultIpnsKeypair,
  type VaultInit,
  type EncryptedVaultKeys,
} from './vault';

// Key hierarchy and derivation
export { deriveKey, deriveContextKey, generateFolderKey, type DeriveKeyParams } from './keys';

// AES-256-GCM symmetric encryption
export { encryptAesGcm, decryptAesGcm, sealAesGcm, unsealAesGcm } from './aes';

// AES-256-CTR streaming encryption (random-access decryption for media)
export { encryptAesCtr, decryptAesCtr, decryptAesCtrRange } from './aes';

// ECIES secp256k1 key wrapping
export { wrapKey, unwrapKey } from './ecies';

// Ed25519 signing for IPNS
export { generateEd25519Keypair, type Ed25519Keypair } from './ed25519';
export { signEd25519, verifyEd25519 } from './ed25519/sign';

// IPNS record creation and signing utilities
export {
  createIpnsRecord,
  deriveIpnsName,
  marshalIpnsRecord,
  unmarshalIpnsRecord,
  signIpnsData,
  IPNS_SIGNATURE_PREFIX,
  type IPNSRecord,
} from './ipns';

// Folder metadata types and encryption
export {
  encryptFolderMetadata,
  decryptFolderMetadata,
  isV2Metadata,
  validateFolderMetadata,
  type FolderMetadata,
  type FolderChild,
  type FolderEntry,
  type FileEntry,
  type EncryptedFolderMetadata,
  type FolderMetadataV2,
  type FolderChildV2,
  type AnyFolderMetadata,
} from './folder';

// Per-file IPNS metadata types and encryption
export {
  deriveFileIpnsKeypair,
  encryptFileMetadata,
  decryptFileMetadata,
  validateFileMetadata,
  type FileMetadata,
  type FilePointer,
  type EncryptedFileMetadata,
} from './file';

// Device registry types and encryption
export {
  encryptRegistry,
  decryptRegistry,
  deriveRegistryIpnsKeypair,
  validateDeviceRegistry,
  type DeviceEntry,
  type DeviceRegistry,
  type DeviceAuthStatus,
  type DevicePlatform,
} from './registry';

// Device identity (per-device Ed25519 keypair)
export { generateDeviceKeypair, deriveDeviceId, type DeviceKeypair } from './device';

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
  generateCtrIv,
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
  ECIES_MIN_CIPHERTEXT_SIZE,
  AES_GCM_ALGORITHM,
  AES_CTR_IV_SIZE,
  AES_CTR_NONCE_SIZE,
  AES_CTR_LENGTH,
  AES_CTR_ALGORITHM,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
} from './constants';
