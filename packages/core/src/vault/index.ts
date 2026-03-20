/**
 * @cipherbox/core - Vault Management
 *
 * Vault initialization, key encryption/decryption.
 * IPNS key derivation remains in @cipherbox/crypto.
 */

export { initializeVault, encryptVaultKeys, decryptVaultKeys } from './init';
export type { VaultInit, EncryptedVaultKeys } from './types';
