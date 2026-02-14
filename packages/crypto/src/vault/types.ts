/**
 * @cipherbox/crypto - Vault Types
 *
 * Type definitions for vault initialization and encrypted key storage.
 */

import type { Ed25519Keypair } from '../ed25519';

/**
 * Result of vault initialization (plaintext, in-memory only).
 *
 * These keys are NEVER persisted to storage - they exist only in memory.
 * When the user logs out or refreshes, keys are re-derived from Web3Auth
 * or wallet signature.
 */
export type VaultInit = {
  /** 32-byte AES key for root folder encryption */
  rootFolderKey: Uint8Array;
  /** Ed25519 keypair for signing root IPNS records */
  rootIpnsKeypair: Ed25519Keypair;
};

/**
 * Vault keys encrypted for server storage (zero-knowledge).
 *
 * The server stores these encrypted blobs without any knowledge of
 * the plaintext keys. Only the user's ECIES private key can decrypt them.
 *
 * The IPNS public key is NOT stored -- it is derived from the IPNS private
 * key after decryption (deterministic Ed25519 derivation).
 */
export type EncryptedVaultKeys = {
  /** Root folder key ECIES-wrapped with user's publicKey */
  encryptedRootFolderKey: Uint8Array;
  /** IPNS private key ECIES-wrapped with user's publicKey */
  encryptedIpnsPrivateKey: Uint8Array;
};
