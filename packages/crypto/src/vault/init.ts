/**
 * @cipherbox/crypto - Vault Initialization
 *
 * Functions for initializing new vaults and encrypting/decrypting vault keys.
 *
 * Vault lifecycle:
 * 1. First sign-in: initializeVault() creates new keys
 * 2. encryptVaultKeys() wraps keys for server storage
 * 3. Server stores encrypted blobs (zero-knowledge)
 * 4. Login: Server returns encrypted blobs
 * 5. decryptVaultKeys() recovers plaintext keys in memory
 */

import { generateFileKey } from '../utils/random';
import { generateEd25519Keypair, type Ed25519Keypair } from '../ed25519';
import { wrapKey, unwrapKey } from '../ecies';
import type { VaultInit, EncryptedVaultKeys } from './types';

/**
 * Initialize a new vault with fresh keys.
 *
 * Called on first sign-in when no vault exists for the user.
 * Generates random root folder key and Ed25519 keypair for IPNS.
 *
 * @returns VaultInit with plaintext keys (keep in memory only!)
 *
 * @example
 * ```typescript
 * const vault = await initializeVault();
 * const encrypted = await encryptVaultKeys(vault, userPublicKey);
 * // Send encrypted to server for storage
 * ```
 */
export async function initializeVault(): Promise<VaultInit> {
  // Generate random 32-byte key for root folder encryption
  const rootFolderKey = generateFileKey();

  // Generate Ed25519 keypair for signing root IPNS records
  const rootIpnsKeypair = generateEd25519Keypair();

  return {
    rootFolderKey,
    rootIpnsKeypair,
  };
}

/**
 * Encrypt vault keys for server storage.
 *
 * Uses ECIES to wrap keys with user's secp256k1 public key.
 * Server stores the encrypted blobs without knowing the contents.
 *
 * @param vault - Plaintext vault keys from initializeVault()
 * @param userPublicKey - 65-byte uncompressed secp256k1 public key
 * @returns Encrypted keys ready for server storage
 *
 * @example
 * ```typescript
 * const encrypted = await encryptVaultKeys(vault, userPublicKey);
 * await api.storeVaultKeys(encrypted);
 * ```
 */
export async function encryptVaultKeys(
  vault: VaultInit,
  userPublicKey: Uint8Array
): Promise<EncryptedVaultKeys> {
  // ECIES-wrap the root folder key
  const encryptedRootFolderKey = await wrapKey(vault.rootFolderKey, userPublicKey);

  // ECIES-wrap the IPNS private key
  const encryptedIpnsPrivateKey = await wrapKey(vault.rootIpnsKeypair.privateKey, userPublicKey);

  return {
    encryptedRootFolderKey,
    encryptedIpnsPrivateKey,
    // Public key is not secret - stored in plaintext for IPNS name derivation
    rootIpnsPublicKey: vault.rootIpnsKeypair.publicKey,
  };
}

/**
 * Decrypt vault keys from server storage.
 *
 * Uses user's ECIES private key to unwrap the stored keys.
 * Called on every login to recover keys in memory.
 *
 * @param encrypted - Encrypted keys from server
 * @param userPrivateKey - 32-byte secp256k1 private key
 * @returns Plaintext vault keys (keep in memory only!)
 *
 * @example
 * ```typescript
 * const encrypted = await api.getVaultKeys();
 * const vault = await decryptVaultKeys(encrypted, userPrivateKey);
 * // Use vault.rootFolderKey for file operations
 * ```
 */
export async function decryptVaultKeys(
  encrypted: EncryptedVaultKeys,
  userPrivateKey: Uint8Array
): Promise<VaultInit> {
  // ECIES-unwrap the root folder key
  const rootFolderKey = await unwrapKey(encrypted.encryptedRootFolderKey, userPrivateKey);

  // ECIES-unwrap the IPNS private key
  const ipnsPrivateKey = await unwrapKey(encrypted.encryptedIpnsPrivateKey, userPrivateKey);

  // Reconstruct the Ed25519 keypair (private key + stored public key)
  const rootIpnsKeypair: Ed25519Keypair = {
    privateKey: ipnsPrivateKey,
    publicKey: encrypted.rootIpnsPublicKey,
  };

  return {
    rootFolderKey,
    rootIpnsKeypair,
  };
}
