/**
 * @cipherbox/crypto - Vault Management
 *
 * Vault initialization, key encryption/decryption, and IPNS derivation.
 */

export { initializeVault, encryptVaultKeys, decryptVaultKeys } from './init';
export { deriveVaultIpnsKeypair } from './derive-ipns';
export type { VaultInit, EncryptedVaultKeys } from './types';
