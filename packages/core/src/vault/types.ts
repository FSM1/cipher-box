/**
 * @cipherbox/core - Vault Types
 *
 * Type definitions for vault initialization and encrypted key storage.
 * v3 two-key design (NODE-06): carries both rootReadKey (for sealed read-bodies)
 * and rootWriteKey (for sealed write-bodies) in independent ECIES envelopes.
 */

import type { Ed25519Keypair } from '@cipherbox/crypto';

/**
 * Result of vault initialization (plaintext, in-memory only).
 *
 * These keys are NEVER persisted to storage - they exist only in memory.
 * When the user logs out or refreshes, keys are re-derived from Web3Auth
 * or wallet signature.
 *
 * rootReadKey and rootWriteKey are independently generated (not derived
 * from each other or from the Ed25519 keypair — RESEARCH Open Q2 / T-62-08).
 */
export type VaultInit = {
  /** 32-byte AES key for sealing root node read-bodies */
  rootReadKey: Uint8Array;
  /** 32-byte AES key for sealing root node write-bodies (independent random key) */
  rootWriteKey: Uint8Array;
  /** Ed25519 keypair for signing root IPNS records */
  rootIpnsKeypair: Ed25519Keypair;
};

/**
 * Vault keys encrypted for server storage (zero-knowledge).
 *
 * The server stores these encrypted blobs without any knowledge of
 * the plaintext keys. Only the user's ECIES private key can decrypt them.
 *
 * Both root keys are ECIES-wrapped independently with the user's publicKey.
 * The v3 blob envelope (vault/blob.ts) carries them in a single binary payload:
 *   0x03 | u16_BE(readLen) | ECIES(rootReadKey) | u16_BE(writeLen) | ECIES(rootWriteKey)
 *
 * The IPNS public key is NOT stored -- it is derived from the IPNS private
 * key after decryption (deterministic Ed25519 derivation).
 */
export type EncryptedVaultKeys = {
  /** rootReadKey ECIES-wrapped with user's publicKey */
  encryptedRootReadKey: Uint8Array;
  /** rootWriteKey ECIES-wrapped with user's publicKey */
  encryptedRootWriteKey: Uint8Array;
  /** IPNS private key ECIES-wrapped with user's publicKey */
  encryptedIpnsPrivateKey: Uint8Array;
};

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
