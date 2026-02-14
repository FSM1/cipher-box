/**
 * @cipherbox/crypto - Vault Initialization
 *
 * Functions for initializing new vaults and encrypting/decrypting vault keys.
 *
 * Vault lifecycle:
 * 1. First sign-in: initializeVault(userPrivateKey) creates deterministic IPNS keypair + random folder key
 * 2. encryptVaultKeys() wraps keys for server storage
 * 3. Server stores encrypted blobs (zero-knowledge)
 * 4. Login: Server returns encrypted blobs
 * 5. decryptVaultKeys() recovers plaintext keys in memory
 */

import { generateFileKey } from '../utils/random';
import { wrapKey, unwrapKey } from '../ecies';
import * as ed from '@noble/ed25519';
import { deriveVaultIpnsKeypair } from './derive-ipns';
import type { Ed25519Keypair } from '../ed25519';
import type { VaultInit, EncryptedVaultKeys } from './types';

/**
 * Initialize a new vault with deterministic IPNS keypair and random folder key.
 *
 * Called on first sign-in when no vault exists for the user.
 * The IPNS keypair is derived deterministically from the user's privateKey
 * via HKDF, enabling self-sovereign vault recovery. The root folder key
 * is randomly generated (no reason for it to be deterministic).
 *
 * @param userPrivateKey - 32-byte secp256k1 private key
 * @returns VaultInit with plaintext keys (keep in memory only!)
 *
 * @example
 * ```typescript
 * const vault = await initializeVault(userPrivateKey);
 * const encrypted = await encryptVaultKeys(vault, userPublicKey);
 * // Send encrypted to server for storage
 * ```
 */
export async function initializeVault(userPrivateKey: Uint8Array): Promise<VaultInit> {
  // Generate random 32-byte key for root folder encryption
  const rootFolderKey = generateFileKey();

  // Derive deterministic Ed25519 keypair for signing root IPNS records
  const derived = await deriveVaultIpnsKeypair(userPrivateKey);
  const rootIpnsKeypair: Ed25519Keypair = {
    privateKey: derived.privateKey,
    publicKey: derived.publicKey,
  };

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
 * The IPNS public key is NOT stored -- it is derivable from the private key.
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
  };
}

/**
 * Decrypt vault keys from server storage.
 *
 * Uses user's ECIES private key to unwrap the stored keys.
 * The IPNS public key is derived from the decrypted private key
 * (deterministic Ed25519 derivation) rather than being stored.
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

  // Derive the Ed25519 public key from the private key (deterministic)
  const ipnsPublicKey = await ed.getPublicKeyAsync(ipnsPrivateKey);

  // Reconstruct the Ed25519 keypair
  const rootIpnsKeypair: Ed25519Keypair = {
    privateKey: ipnsPrivateKey,
    publicKey: ipnsPublicKey,
  };

  return {
    rootFolderKey,
    rootIpnsKeypair,
  };
}
