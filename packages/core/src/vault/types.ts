/**
 * @cipherbox/core - Vault Types
 *
 * Type definitions for vault initialization and encrypted key storage.
 */

import type { Ed25519Keypair } from '@cipherbox/crypto';

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

/**
 * Parsed vault blob v2 components.
 *
 * Binary format: 0x02 | uint16_BE(key_len) | encrypted_key | encrypted_metadata_json
 *
 * The encrypted key is the ECIES-wrapped rootFolderKey (typically 129 bytes
 * for a 32-byte plaintext key). The encrypted metadata JSON is the existing
 * AES-GCM encrypted folder metadata (variable length).
 */
export type VaultBlobV2 = {
  /** ECIES-encrypted rootFolderKey (129 bytes for 32-byte key) */
  encryptedRootFolderKey: Uint8Array;
  /** AES-GCM encrypted folder metadata JSON bytes */
  encryptedMetadataJson: Uint8Array;
};
