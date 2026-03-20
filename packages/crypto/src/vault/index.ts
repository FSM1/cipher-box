/**
 * @cipherbox/crypto - Vault IPNS Key Derivation
 *
 * Only the deterministic IPNS keypair derivation remains in crypto.
 * Vault initialization and key management moved to @cipherbox/core.
 */

export { deriveVaultIpnsKeypair } from './derive-ipns';
