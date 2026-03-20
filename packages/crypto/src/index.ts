/**
 * @cipherbox/crypto
 *
 * Pure cryptographic primitives and key derivation for CipherBox.
 * Provides AES-256-GCM/CTR encryption, ECIES key wrapping, Ed25519 signing,
 * and key hierarchy management.
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

export const CRYPTO_VERSION = '0.2.0';

// Vault IPNS key derivation (only derive-ipns remains in crypto)
export { deriveVaultIpnsKeypair } from './vault';

// Key hierarchy and derivation
export { deriveKey, deriveContextKey, generateFolderKey, type DeriveKeyParams } from './keys';

// AES-256-GCM symmetric encryption
export { encryptAesGcm, decryptAesGcm, sealAesGcm, unsealAesGcm } from './aes';

// AES-256-CTR streaming encryption (random-access decryption for media)
export { encryptAesCtr, decryptAesCtr, decryptAesCtrRange } from './aes';

// ECIES secp256k1 key wrapping
export { wrapKey, unwrapKey, reWrapKey } from './ecies';

// Ed25519 signing for IPNS
export { generateEd25519Keypair, type Ed25519Keypair } from './ed25519';
export { signEd25519, verifyEd25519 } from './ed25519/sign';

// IPNS name derivation (kept in crypto as a pure crypto utility)
export { deriveIpnsName } from './ipns/derive-name';

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

// ============================================================
// Transitional re-exports from @cipherbox/core
// These maintain backward compatibility during the SDK migration.
// TODO(19.1-06): Remove these re-exports in the final cleanup plan.
// ============================================================
export {
  // Folder metadata
  encryptFolderMetadata,
  decryptFolderMetadata,
  validateFolderMetadata,
  type FolderMetadata,
  type FolderChild,
  type FolderEntry,
  type EncryptedFolderMetadata,
  // File metadata
  deriveFileIpnsKeypair,
  generateFileIpnsKeypair,
  encryptFileMetadata,
  decryptFileMetadata,
  validateFileMetadata,
  type FileMetadata,
  type FilePointer,
  type EncryptedFileMetadata,
  type VersionEntry,
  // Device registry
  encryptRegistry,
  decryptRegistry,
  deriveRegistryIpnsKeypair,
  validateDeviceRegistry,
  type DeviceEntry,
  type DeviceRegistry,
  type DeviceAuthStatus,
  type DevicePlatform,
  // Recycle bin
  encryptBinMetadata,
  decryptBinMetadata,
  deriveBinIpnsKeypair,
  validateBinMetadata,
  type BinEntry,
  type RecycleBinMetadata,
  // Vault init
  initializeVault,
  encryptVaultKeys,
  decryptVaultKeys,
  type VaultInit,
  type EncryptedVaultKeys,
  // IPNS records
  createIpnsRecord,
  marshalIpnsRecord,
  unmarshalIpnsRecord,
  signIpnsData,
  IPNS_SIGNATURE_PREFIX,
  type IPNSRecord,
} from '@cipherbox/core';
