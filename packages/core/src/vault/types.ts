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
 * Vault key blob v2 is now a simple binary envelope: 0x02 | uint16_BE(key_len) | encrypted_key
 *
 * deserializeVaultBlobV2 returns the ECIES-encrypted rootFolderKey directly as Uint8Array.
 * No separate type needed.
 */

/**
 * BYO-IPFS configuration stored in vault metadata on IPFS.
 * Encrypted with user's key, decrypted client-side only.
 * Server never sees this data (zero-knowledge preserved).
 *
 * Default when absent: { pinningMode: 'cipherbox', externalProvider: null }
 */
export type ByoIpfsConfig = {
  /** User-selected pinning mode */
  pinningMode: 'cipherbox' | 'external' | 'dual';
  /** External provider config (null when mode is 'cipherbox') */
  externalProvider: {
    endpoint: string;
    authToken: string;
    protocol: 'psa' | 'kubo' | 'pinata';
    providerName?: string;
  } | null;
};

/**
 * User-configurable vault parameters stored as encrypted IPNS entry.
 * Encrypted with user's key, decrypted client-side only.
 * Server never sees this data (zero-knowledge preserved).
 *
 * Default when absent: { version: 'v1', recycleBinRetentionDays: 30,
 *   deleteBehavior: 'bin', maxVersionsPerFile: 10, versionCooldownMinutes: 15 }
 */
export type VaultSettings = {
  /** Schema version for future migrations */
  version: 'v1';
  /** Recycle bin retention period in days (default: 30, range: 0-365; 0 disables / immediate purge) */
  recycleBinRetentionDays: number;
  /** Delete behavior: 'bin' = soft delete to recycle bin, 'permanent' = immediate hard delete */
  deleteBehavior: 'bin' | 'permanent';
  /** Maximum number of past versions retained per file (default: 10, range: 0-100) */
  maxVersionsPerFile: number;
  /** Cooldown period for automatic version creation in minutes (default: 15, range: 0-1440) */
  versionCooldownMinutes: number;
};
