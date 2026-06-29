/**
 * @cipherbox/core - Vault Management
 *
 * Vault initialization, key encryption/decryption, and blob v3 format.
 * IPNS key derivation remains in @cipherbox/crypto.
 */

export { initializeVault, encryptVaultKeys, decryptVaultKeys } from './init';
export { serializeVaultBlobV3, deserializeVaultBlobV3, BLOB_V3_VERSION } from './blob';
export { DEFAULT_VAULT_SETTINGS, validateVaultSettings } from './settings';
export type { VaultInit, EncryptedVaultKeys, ByoIpfsConfig, VaultSettings } from './types';
