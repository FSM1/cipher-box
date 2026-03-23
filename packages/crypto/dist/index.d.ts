import { IPNSRecord } from 'ipns';
export { IPNSRecord } from 'ipns';

/**
 * @cipherbox/crypto - Ed25519 Key Generation
 *
 * Generates Ed25519 keypairs for IPNS record signing.
 * Each folder in CipherBox has its own Ed25519 keypair.
 */
/**
 * Ed25519 keypair for IPNS operations.
 */
type Ed25519Keypair = {
    /** 32-byte Ed25519 public key */
    publicKey: Uint8Array;
    /** 32-byte Ed25519 private key (seed) */
    privateKey: Uint8Array;
};
/**
 * Generates a new Ed25519 keypair.
 *
 * @returns Ed25519 keypair with 32-byte public and private keys
 */
declare function generateEd25519Keypair(): Ed25519Keypair;

/**
 * @cipherbox/crypto - Ed25519 Signing
 *
 * Sign and verify operations using Ed25519.
 * Used for IPNS record signing.
 */
/**
 * Signs a message with an Ed25519 private key.
 *
 * @param message - The message to sign
 * @param privateKey - 32-byte Ed25519 private key
 * @returns 64-byte Ed25519 signature
 * @throws CryptoError if privateKey is invalid or signing fails
 */
declare function signEd25519(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
/**
 * Verifies an Ed25519 signature.
 *
 * @param signature - 64-byte Ed25519 signature
 * @param message - The original message
 * @param publicKey - 32-byte Ed25519 public key
 * @returns true if signature is valid, false otherwise
 */
declare function verifyEd25519(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean>;

/**
 * @cipherbox/crypto - Vault Types
 *
 * Type definitions for vault initialization and encrypted key storage.
 */

/**
 * Result of vault initialization (plaintext, in-memory only).
 *
 * These keys are NEVER persisted to storage - they exist only in memory.
 * When the user logs out or refreshes, keys are re-derived from Web3Auth
 * or wallet signature.
 */
type VaultInit = {
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
 */
type EncryptedVaultKeys = {
    /** Root folder key ECIES-wrapped with user's publicKey */
    encryptedRootFolderKey: Uint8Array;
    /** IPNS private key ECIES-wrapped with user's publicKey */
    encryptedIpnsPrivateKey: Uint8Array;
    /** Public key for IPNS name derivation (not secret) */
    rootIpnsPublicKey: Uint8Array;
};

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
declare function initializeVault(): Promise<VaultInit>;
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
declare function encryptVaultKeys(vault: VaultInit, userPublicKey: Uint8Array): Promise<EncryptedVaultKeys>;
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
declare function decryptVaultKeys(encrypted: EncryptedVaultKeys, userPrivateKey: Uint8Array): Promise<VaultInit>;

/**
 * @cipherbox/crypto - HKDF Key Derivation
 *
 * HKDF-SHA256 key derivation using Web Crypto API.
 * Used for deriving context-specific keys from master key material.
 */
/**
 * Parameters for HKDF key derivation.
 */
type DeriveKeyParams = {
    /** Input key material (e.g., master key, signature) */
    inputKey: Uint8Array;
    /** Salt for HKDF (domain separation) */
    salt: Uint8Array;
    /** Info/context for HKDF (additional context) */
    info: Uint8Array;
    /** Output length in bytes (defaults to 32) */
    outputLength?: number;
};
/**
 * Derive a key using HKDF-SHA256.
 *
 * @param params - Derivation parameters
 * @returns Derived key bytes
 * @throws CryptoError if derivation fails
 *
 * @example
 * ```typescript
 * const derivedKey = await deriveKey({
 *   inputKey: masterKey,
 *   salt: new TextEncoder().encode('CipherBox-v1'),
 *   info: new TextEncoder().encode('folder-key'),
 *   outputLength: 32
 * });
 * ```
 */
declare function deriveKey(params: DeriveKeyParams): Promise<Uint8Array>;

/**
 * @cipherbox/crypto - Random Generation Utilities
 *
 * Cryptographically secure random number generation using Web Crypto API.
 */
/**
 * Generate cryptographically secure random bytes.
 *
 * @param length - Number of bytes to generate
 * @returns Random bytes
 * @throws CryptoError if crypto.getRandomValues is unavailable
 */
declare function generateRandomBytes(length: number): Uint8Array;
/**
 * Generate a random 256-bit file key for AES-GCM encryption.
 *
 * Each file must use a unique key - never reuse keys across files.
 *
 * @returns 32-byte random key
 */
declare function generateFileKey(): Uint8Array;
/**
 * Generate a random 96-bit IV for AES-GCM encryption.
 *
 * Each encryption operation must use a unique IV with the same key.
 * NEVER reuse an IV with the same key - this would be catastrophic for security.
 *
 * @returns 12-byte random IV
 */
declare function generateIv(): Uint8Array;

/**
 * @cipherbox/crypto - Key Hierarchy Functions
 *
 * Functions for deriving and generating keys within the CipherBox hierarchy.
 *
 * Key design decisions (see 03-CONTEXT.md):
 * - Folder keys are randomly generated, then ECIES-wrapped with user's public key
 * - File keys are randomly generated per-file (no deduplication per CRYPT-06)
 * - Context keys are derived deterministically from master keys for specific purposes
 */
/**
 * Derive a context-specific key from a master key.
 *
 * Uses HKDF-SHA256 with CipherBox-specific salt and the provided context.
 * Same master key + context always produces the same derived key.
 *
 * @param masterKey - 32-byte master key material
 * @param context - Context string for derivation (e.g., 'root-folder', 'ipns-key')
 * @returns 32-byte derived key
 *
 * @example
 * ```typescript
 * const rootKey = await deriveContextKey(vaultMasterKey, 'root-folder');
 * ```
 */
declare function deriveContextKey(masterKey: Uint8Array, context: string): Promise<Uint8Array>;
/**
 * Generate a new random folder key.
 *
 * Folder keys are randomly generated, NOT derived from a hierarchy.
 * They are then ECIES-wrapped with the user's public key for storage.
 *
 * @returns Random 32-byte key suitable for AES-256-GCM
 */
declare function generateFolderKey(): Promise<Uint8Array>;

/**
 * @cipherbox/crypto - AES-256-GCM Encryption
 *
 * Symmetric encryption for file content and folder metadata.
 * Uses Web Crypto API for hardware-accelerated encryption.
 */
/**
 * Encrypt data using AES-256-GCM.
 *
 * Each encryption MUST use a unique IV with the same key.
 * Reusing IV+key pairs is catastrophic for AES-GCM security.
 *
 * @param plaintext - Data to encrypt
 * @param key - 32-byte AES key
 * @param iv - 12-byte initialization vector (MUST be unique per encryption)
 * @returns Ciphertext including 16-byte authentication tag
 * @throws CryptoError with generic message on any failure
 */
declare function encryptAesGcm(plaintext: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array>;

/**
 * @cipherbox/crypto - AES-256-GCM Decryption
 *
 * Symmetric decryption for file content and folder metadata.
 * Uses Web Crypto API for hardware-accelerated decryption.
 */
/**
 * Decrypt data encrypted with AES-256-GCM.
 *
 * Automatically verifies the authentication tag during decryption.
 * Throws on any failure (wrong key, modified ciphertext, wrong IV).
 *
 * @param ciphertext - Encrypted data including 16-byte authentication tag
 * @param key - 32-byte AES key (must match encryption key)
 * @param iv - 12-byte initialization vector (must match encryption IV)
 * @returns Decrypted plaintext
 * @throws CryptoError with generic message on any failure
 */
declare function decryptAesGcm(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array>;

/**
 * @cipherbox/crypto - AES-256-GCM Seal/Unseal
 *
 * Higher-level API that handles IV generation and binding automatically.
 * This prevents IV mismanagement by ensuring IV is always stored with ciphertext.
 *
 * Format: IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)
 */
/**
 * Seal data using AES-256-GCM with automatic IV generation.
 *
 * This is the recommended API for encryption. It automatically:
 * 1. Generates a fresh random IV
 * 2. Encrypts the plaintext
 * 3. Prepends the IV to the ciphertext
 *
 * The returned sealed data can be safely stored - the IV is included.
 *
 * @param plaintext - Data to encrypt
 * @param key - 32-byte AES key
 * @returns Sealed data: IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)
 * @throws CryptoError with generic message on any failure
 */
declare function sealAesGcm(plaintext: Uint8Array, key: Uint8Array): Promise<Uint8Array>;
/**
 * Unseal data encrypted with sealAesGcm.
 *
 * This is the recommended API for decryption. It automatically:
 * 1. Extracts the IV from the sealed data
 * 2. Decrypts and verifies the ciphertext
 *
 * @param sealed - Sealed data from sealAesGcm
 * @param key - 32-byte AES key (must match encryption key)
 * @returns Decrypted plaintext
 * @throws CryptoError with generic message on any failure
 */
declare function unsealAesGcm(sealed: Uint8Array, key: Uint8Array): Promise<Uint8Array>;

/**
 * @cipherbox/crypto - ECIES Key Wrapping (Encryption)
 *
 * Wraps symmetric keys using ECIES with secp256k1.
 * Uses eciesjs library which handles ephemeral keys, ECDH, HKDF, and AES-GCM internally.
 */
/**
 * Wrap a key using ECIES encryption.
 *
 * Encrypts a symmetric key (or any data) to a recipient's public key.
 * Only the holder of the corresponding private key can unwrap it.
 *
 * Each call produces different ciphertext due to ephemeral key generation.
 *
 * @param key - Data to wrap (typically a 32-byte file key)
 * @param recipientPublicKey - 65-byte uncompressed secp256k1 public key
 * @returns Wrapped key ciphertext
 * @throws CryptoError with generic message on any failure
 */
declare function wrapKey(key: Uint8Array, recipientPublicKey: Uint8Array): Promise<Uint8Array>;

/**
 * @cipherbox/crypto - ECIES Key Unwrapping (Decryption)
 *
 * Unwraps symmetric keys using ECIES with secp256k1.
 * Uses eciesjs library which handles ECDH, HKDF, and AES-GCM internally.
 */
/**
 * Unwrap a key using ECIES decryption.
 *
 * Decrypts a wrapped key using the recipient's private key.
 * Only succeeds if the key was wrapped with the corresponding public key.
 *
 * @param wrappedKey - ECIES ciphertext from wrapKey
 * @param privateKey - 32-byte secp256k1 private key
 * @returns Original unwrapped key
 * @throws CryptoError with generic message on any failure
 */
declare function unwrapKey(wrappedKey: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;

/**
 * @cipherbox/crypto - IPNS Record Creation
 *
 * Creates IPNS records using the ipns npm package.
 * Handles conversion from @noble/ed25519 raw keys to libp2p format.
 */

/**
 * Creates an IPNS record signed with the given Ed25519 private key.
 *
 * The ipns package handles:
 * - CBOR encoding of record data
 * - V1 and V2 signature creation
 * - Proper validity timestamp formatting
 *
 * @param ed25519PrivateKey - 32-byte Ed25519 private key (seed) from @noble/ed25519
 * @param value - IPFS path to point to (e.g., "/ipfs/bafy...")
 * @param sequenceNumber - Monotonically increasing sequence number
 * @param lifetimeMs - Record validity lifetime in milliseconds (default: 24 hours)
 * @returns IPNS record ready for marshaling and publishing
 * @throws CryptoError if key conversion or record creation fails
 */
declare function createIpnsRecord(ed25519PrivateKey: Uint8Array, value: string, sequenceNumber: bigint, lifetimeMs?: number): Promise<IPNSRecord>;

/**
 * @cipherbox/crypto - IPNS Name Derivation
 *
 * Derives IPNS name (CIDv1 with libp2p-key codec) from Ed25519 public key.
 */
/**
 * Derives the IPNS name from an Ed25519 public key.
 *
 * The IPNS name is a CIDv1 with:
 * - libp2p-key multicodec (0x72)
 * - identity multihash containing the protobuf-encoded public key
 *
 * This produces names starting with "k51..." in base36 encoding.
 *
 * @param ed25519PublicKey - 32-byte Ed25519 public key
 * @returns IPNS name string (e.g., "k51qzi5uqu5...")
 * @throws CryptoError if public key is invalid
 */
declare function deriveIpnsName(ed25519PublicKey: Uint8Array): Promise<string>;

/**
 * @cipherbox/crypto - IPNS Record Marshaling
 *
 * Wrappers around ipns package serialization functions.
 */

/**
 * Serializes an IPNS record to bytes for transmission.
 *
 * The marshaled format is protobuf-encoded and compatible with:
 * - Delegated Routing API (PUT /routing/v1/ipns/{name})
 * - IPFS DHT storage
 * - Kubo RPC API
 *
 * @param record - IPNS record object to serialize
 * @returns Protobuf-encoded bytes
 */
declare function marshalIpnsRecord(record: IPNSRecord): Uint8Array;
/**
 * Deserializes an IPNS record from bytes.
 *
 * @param bytes - Protobuf-encoded IPNS record
 * @returns Parsed IPNS record object
 * @throws Error if bytes are not a valid IPNS record
 */
declare function unmarshalIpnsRecord(bytes: Uint8Array): IPNSRecord;

/**
 * @cipherbox/crypto - IPNS Record Signing
 *
 * Utilities for signing IPNS records according to IPFS spec.
 * See: https://specs.ipfs.tech/ipns/ipns-record/
 *
 * Note: This module provides the signing primitive. Full IPNS record
 * marshaling (protobuf + CBOR) is handled by the `ipns` npm package
 * in Phase 5. This function signs the raw CBOR data.
 */
/**
 * IPNS signature prefix per IPFS spec.
 * This is "ipns-signature:" as UTF-8 bytes.
 * The prefix is concatenated with CBOR data before signing.
 */
declare const IPNS_SIGNATURE_PREFIX: Uint8Array<ArrayBuffer>;
/**
 * Signs IPNS record data with Ed25519.
 *
 * Per IPFS IPNS spec, the signature is computed over:
 * "ipns-signature:" + cborData
 *
 * @param cborData - The CBOR-encoded IPNS record data to sign
 * @param privateKey - 32-byte Ed25519 private key
 * @returns 64-byte Ed25519 signature
 * @throws CryptoError if signing fails
 */
declare function signIpnsData(cborData: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;

/**
 * @cipherbox/crypto - Folder Metadata Types
 *
 * Type definitions for encrypted folder metadata stored in IPNS records.
 */
/**
 * Decrypted folder metadata structure.
 * The entire FolderMetadata object is encrypted as a single blob with AES-256-GCM.
 */
type FolderMetadata = {
    /** Schema version for future migrations */
    version: 'v1';
    /** Files and subfolders in this folder */
    children: FolderChild[];
};
/**
 * A child entry can be either a folder or a file.
 */
type FolderChild = FolderEntry | FileEntry;
/**
 * Subfolder entry within folder metadata.
 * Contains ECIES-wrapped keys for accessing the subfolder.
 */
type FolderEntry = {
    type: 'folder';
    /** UUID for internal reference */
    id: string;
    /** Folder name (plaintext, since whole metadata is encrypted) */
    name: string;
    /** IPNS name for this subfolder (k51... format) */
    ipnsName: string;
    /** Hex-encoded ECIES-wrapped Ed25519 private key for IPNS signing */
    ipnsPrivateKeyEncrypted: string;
    /** Hex-encoded ECIES-wrapped AES-256 key for decrypting subfolder metadata */
    folderKeyEncrypted: string;
    /** Creation timestamp (Unix ms) */
    createdAt: number;
    /** Last modification timestamp (Unix ms) */
    modifiedAt: number;
};
/**
 * File entry within folder metadata.
 * Contains reference to encrypted file on IPFS and ECIES-wrapped decryption key.
 */
type FileEntry = {
    type: 'file';
    /** UUID for internal reference */
    id: string;
    /** File name (plaintext, since whole metadata is encrypted) */
    name: string;
    /** IPFS CID of the encrypted file content */
    cid: string;
    /** Hex-encoded ECIES-wrapped AES-256 key for decrypting file */
    fileKeyEncrypted: string;
    /** Hex-encoded IV used for file encryption */
    fileIv: string;
    /** Encryption mode (always GCM for v1.0) */
    encryptionMode: 'GCM';
    /** Original file size in bytes (before encryption) */
    size: number;
    /** Creation timestamp (Unix ms) */
    createdAt: number;
    /** Last modification timestamp (Unix ms) */
    modifiedAt: number;
};
/**
 * Encrypted folder metadata for storage/transmission.
 * This is what gets uploaded to IPFS and referenced by IPNS.
 */
type EncryptedFolderMetadata = {
    /** Hex-encoded 12-byte IV for AES-GCM */
    iv: string;
    /** Base64-encoded AES-GCM ciphertext (includes 16-byte auth tag) */
    data: string;
};

/**
 * @cipherbox/crypto - Folder Metadata Encryption
 *
 * Encrypts and decrypts folder metadata using AES-256-GCM.
 * Folder metadata is JSON serialized before encryption.
 */

/**
 * Encrypts folder metadata with AES-256-GCM.
 *
 * @param metadata - Plaintext folder metadata object
 * @param folderKey - 32-byte AES key for this folder
 * @returns Encrypted metadata with IV (hex) and ciphertext (base64)
 */
declare function encryptFolderMetadata(metadata: FolderMetadata, folderKey: Uint8Array): Promise<EncryptedFolderMetadata>;
/**
 * Decrypts folder metadata encrypted with AES-256-GCM.
 *
 * @param encrypted - Encrypted metadata with IV (hex) and ciphertext (base64)
 * @param folderKey - 32-byte AES key for this folder
 * @returns Decrypted folder metadata object
 * @throws CryptoError if decryption fails (wrong key, corrupted data, etc.)
 */
declare function decryptFolderMetadata(encrypted: EncryptedFolderMetadata, folderKey: Uint8Array): Promise<FolderMetadata>;

/**
 * @cipherbox/crypto - Encoding Utilities
 *
 * Hex and byte conversion utilities.
 */
/**
 * Convert hex string to Uint8Array.
 * Handles optional 0x prefix.
 *
 * @param hex - Hex string (with or without 0x prefix)
 * @returns Byte array
 */
declare function hexToBytes(hex: string): Uint8Array;
/**
 * Convert Uint8Array to hex string (no prefix).
 *
 * @param bytes - Byte array
 * @returns Hex string without 0x prefix
 */
declare function bytesToHex(bytes: Uint8Array): string;
/**
 * Concatenate multiple Uint8Arrays into one.
 *
 * @param arrays - Arrays to concatenate
 * @returns Combined array
 */
declare function concatBytes(...arrays: Uint8Array[]): Uint8Array;

/**
 * @cipherbox/crypto - Memory Utilities
 *
 * Best-effort memory clearing for sensitive data.
 *
 * IMPORTANT: JavaScript does not guarantee memory clearing.
 * The garbage collector controls actual memory deallocation, and copies
 * may exist in JIT-compiled code or V8 internals. These functions provide
 * best-effort clearing by overwriting buffer contents, but should not be
 * relied upon for absolute security in memory-sensitive contexts.
 */
/**
 * Clear sensitive data from a Uint8Array (best-effort).
 *
 * Overwrites all bytes with zeros. This is a defense-in-depth measure,
 * not a guarantee of secure erasure.
 *
 * @param data - Buffer to clear (null-safe)
 */
declare function clearBytes(data: Uint8Array | null): void;
/**
 * Clear multiple buffers at once.
 *
 * @param buffers - Buffers to clear (null-safe)
 */
declare function clearAll(...buffers: (Uint8Array | null)[]): void;

/**
 * @cipherbox/crypto - Type Definitions
 *
 * Core types for cryptographic operations.
 */
/**
 * User's vault keypair for ECIES operations.
 * Source agnostic - same type whether derived from Web3Auth or external wallet (ADR-001).
 */
type VaultKey = {
    /** 65-byte uncompressed secp256k1 public key */
    publicKey: Uint8Array;
    /** 32-byte secp256k1 private key */
    privateKey: Uint8Array;
};
/**
 * Result of AES-GCM encryption.
 * IV and ciphertext are kept separate for explicit handling.
 */
type EncryptedData = {
    /** Encrypted data including authentication tag */
    ciphertext: Uint8Array;
    /** 12-byte initialization vector */
    iv: Uint8Array;
};
/**
 * Error codes for categorized error handling.
 * Generic messages are still used externally to prevent oracle attacks.
 */
type CryptoErrorCode = 'ENCRYPTION_FAILED' | 'DECRYPTION_FAILED' | 'KEY_WRAPPING_FAILED' | 'KEY_UNWRAPPING_FAILED' | 'INVALID_KEY_SIZE' | 'INVALID_IV_SIZE' | 'INVALID_PUBLIC_KEY_SIZE' | 'INVALID_PUBLIC_KEY_FORMAT' | 'INVALID_PRIVATE_KEY_SIZE' | 'INVALID_SIGNATURE_SIZE' | 'SIGNING_FAILED' | 'RANDOM_GENERATION_FAILED' | 'SECURE_CONTEXT_REQUIRED';
/**
 * Custom error class for cryptographic operations.
 * Provides error codes for internal handling while keeping messages generic.
 */
declare class CryptoError extends Error {
    readonly code: CryptoErrorCode;
    constructor(message: string, code: CryptoErrorCode);
}

/**
 * @cipherbox/crypto - Constants
 *
 * Cryptographic parameters and sizes.
 */
/** AES-256-GCM key size in bytes (256 bits) */
declare const AES_KEY_SIZE = 32;
/** AES-GCM IV size in bytes (96 bits) - optimal for GCM mode */
declare const AES_IV_SIZE = 12;
/** AES-GCM authentication tag size in bytes (128 bits) */
declare const AES_TAG_SIZE = 16;
/** secp256k1 uncompressed public key size in bytes (04 prefix + x + y coordinates) */
declare const SECP256K1_PUBLIC_KEY_SIZE = 65;
/** secp256k1 private key size in bytes */
declare const SECP256K1_PRIVATE_KEY_SIZE = 32;
/** ECIES minimum ciphertext size: ephemeral pubkey (65) + auth tag (16) */
declare const ECIES_MIN_CIPHERTEXT_SIZE: number;
/** AES-GCM algorithm name for Web Crypto API */
declare const AES_GCM_ALGORITHM = "AES-GCM";
/** Ed25519 public key size in bytes */
declare const ED25519_PUBLIC_KEY_SIZE = 32;
/** Ed25519 private key size in bytes */
declare const ED25519_PRIVATE_KEY_SIZE = 32;
/** Ed25519 signature size in bytes */
declare const ED25519_SIGNATURE_SIZE = 64;

/**
 * @cipherbox/crypto
 *
 * Shared cryptographic utilities for CipherBox.
 * Provides AES-256-GCM encryption, ECIES key wrapping, Ed25519 signing,
 * vault initialization, and key hierarchy management.
 *
 * Security principles:
 * - All operations use Web Crypto API or audited libraries (@noble/*, eciesjs)
 * - Error messages are generic to prevent oracle attacks
 * - Keys are Uint8Array - never convert to/from strings for sensitive data
 * - Private keys exist in memory only - never persisted to storage
 *
 * @example
 * ```typescript
 * import {
 *   initializeVault,
 *   encryptVaultKeys,
 *   decryptVaultKeys,
 *   generateFileKey,
 *   generateIv,
 *   encryptAesGcm,
 *   decryptAesGcm,
 *   wrapKey,
 *   unwrapKey
 * } from '@cipherbox/crypto';
 *
 * // Initialize vault on first sign-in
 * const vault = await initializeVault();
 * const encrypted = await encryptVaultKeys(vault, userPublicKey);
 *
 * // Encrypt file content
 * const fileKey = generateFileKey();
 * const iv = generateIv();
 * const ciphertext = await encryptAesGcm(plaintext, fileKey, iv);
 *
 * // Wrap file key with user's public key
 * const wrappedKey = await wrapKey(fileKey, vaultKey.publicKey);
 *
 * // Unwrap and decrypt
 * const unwrappedKey = await unwrapKey(wrappedKey, vaultKey.privateKey);
 * const decrypted = await decryptAesGcm(ciphertext, unwrappedKey, iv);
 * ```
 */
declare const CRYPTO_VERSION = "0.2.0";

export { AES_GCM_ALGORITHM, AES_IV_SIZE, AES_KEY_SIZE, AES_TAG_SIZE, CRYPTO_VERSION, CryptoError, type CryptoErrorCode, type DeriveKeyParams, ECIES_MIN_CIPHERTEXT_SIZE, ED25519_PRIVATE_KEY_SIZE, ED25519_PUBLIC_KEY_SIZE, ED25519_SIGNATURE_SIZE, type Ed25519Keypair, type EncryptedData, type EncryptedFolderMetadata, type EncryptedVaultKeys, type FileEntry, type FolderChild, type FolderEntry, type FolderMetadata, IPNS_SIGNATURE_PREFIX, SECP256K1_PRIVATE_KEY_SIZE, SECP256K1_PUBLIC_KEY_SIZE, type VaultInit, type VaultKey, bytesToHex, clearAll, clearBytes, concatBytes, createIpnsRecord, decryptAesGcm, decryptFolderMetadata, decryptVaultKeys, deriveContextKey, deriveIpnsName, deriveKey, encryptAesGcm, encryptFolderMetadata, encryptVaultKeys, generateEd25519Keypair, generateFileKey, generateFolderKey, generateIv, generateRandomBytes, hexToBytes, initializeVault, marshalIpnsRecord, sealAesGcm, signEd25519, signIpnsData, unmarshalIpnsRecord, unsealAesGcm, unwrapKey, verifyEd25519, wrapKey };
