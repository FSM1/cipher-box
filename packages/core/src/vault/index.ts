/**
 * @cipherbox/core - Vault Management
 *
 * Vault initialization, key encryption/decryption, and blob v2 format.
 * IPNS key derivation remains in @cipherbox/crypto.
 */

export { initializeVault, encryptVaultKeys, decryptVaultKeys } from './init';
export {
  serializeVaultBlobV2,
  deserializeVaultBlobV2,
  detectBlobVersion,
  BLOB_V2_VERSION,
} from './blob';
export { DEFAULT_VAULT_SETTINGS, validateVaultSettings } from './settings';
export type { VaultInit, EncryptedVaultKeys, ByoIpfsConfig, VaultSettings } from './types';
