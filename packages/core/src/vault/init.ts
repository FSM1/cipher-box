/**
 * @cipherbox/core - Vault Initialization
 *
 * Functions for initializing new vaults and encrypting/decrypting vault keys.
 *
 * v3 two-key design (NODE-06): vault carries both rootReadKey (for sealed
 * read-bodies) and rootWriteKey (for sealed write-bodies), each an independent
 * random 32-byte AES key. Neither is derived from the other or from the Ed25519
 * keypair (RESEARCH Open Q2 / T-62-08).
 *
 * Vault lifecycle:
 * 1. First sign-in: initializeVault(userPrivateKey) creates deterministic IPNS keypair + two random root keys
 * 2. encryptVaultKeys() wraps all three keys for server storage
 * 3. Server stores encrypted blobs (zero-knowledge)
 * 4. Login: Server returns encrypted blobs
 * 5. decryptVaultKeys() recovers plaintext keys in memory
 */

import { generateFileKey, wrapKey, unwrapKey, deriveVaultIpnsKeypair } from '@cipherbox/crypto';
import type { Ed25519Keypair } from '@cipherbox/crypto';
import * as ed from '@noble/ed25519';
import type { VaultInit, EncryptedVaultKeys } from './types';

/**
 * Initialize a new vault with deterministic IPNS keypair and two independent random root keys.
 *
 * Called on first sign-in when no vault exists for the user.
 * The IPNS keypair is derived deterministically from the user's privateKey
 * via HKDF, enabling self-sovereign vault recovery. Both rootReadKey and
 * rootWriteKey are independently generated (not derived from each other or
 * from the Ed25519 keypair — the Ed25519 key lives inside the sealed write-body).
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
  // Generate two independent random 32-byte keys for root node seal bodies
  const rootReadKey = generateFileKey();
  const rootWriteKey = generateFileKey();

  // Derive deterministic Ed25519 keypair for signing root IPNS records
  const derived = await deriveVaultIpnsKeypair(userPrivateKey);
  const rootIpnsKeypair: Ed25519Keypair = {
    privateKey: derived.privateKey,
    publicKey: derived.publicKey,
  };

  return {
    rootReadKey,
    rootWriteKey,
    rootIpnsKeypair,
  };
}

/**
 * Encrypt vault keys for server storage.
 *
 * Uses ECIES to wrap all three keys with user's secp256k1 public key.
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
  // ECIES-wrap both root keys independently
  const encryptedRootReadKey = await wrapKey(vault.rootReadKey, userPublicKey);
  const encryptedRootWriteKey = await wrapKey(vault.rootWriteKey, userPublicKey);

  // ECIES-wrap the IPNS private key
  const encryptedIpnsPrivateKey = await wrapKey(vault.rootIpnsKeypair.privateKey, userPublicKey);

  return {
    encryptedRootReadKey,
    encryptedRootWriteKey,
    encryptedIpnsPrivateKey,
  };
}

/**
 * Decrypt vault keys from server storage.
 *
 * Uses user's ECIES private key to unwrap all stored keys.
 * The IPNS public key is derived from the decrypted private key
 * (deterministic Ed25519 derivation) rather than being stored.
 * Called on every login to recover keys in memory.
 *
 * D-09: callee must NOT zero caller-owned buffers. The encrypted blobs
 * are caller-owned and may be reused across sessions.
 *
 * @param encrypted - Encrypted keys from server
 * @param userPrivateKey - 32-byte secp256k1 private key
 * @returns Plaintext vault keys (keep in memory only!)
 *
 * @example
 * ```typescript
 * const encrypted = await api.getVaultKeys();
 * const vault = await decryptVaultKeys(encrypted, userPrivateKey);
 * // Use vault.rootReadKey / vault.rootWriteKey for node seal operations
 * ```
 */
export async function decryptVaultKeys(
  encrypted: EncryptedVaultKeys,
  userPrivateKey: Uint8Array
): Promise<VaultInit> {
  // ECIES-unwrap both root keys
  const rootReadKey = await unwrapKey(encrypted.encryptedRootReadKey, userPrivateKey);
  const rootWriteKey = await unwrapKey(encrypted.encryptedRootWriteKey, userPrivateKey);

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
    rootReadKey,
    rootWriteKey,
    rootIpnsKeypair,
  };
}
