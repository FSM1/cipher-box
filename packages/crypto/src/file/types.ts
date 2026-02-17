/**
 * @cipherbox/crypto - Per-File Metadata Types
 *
 * Type definitions for per-file IPNS metadata records.
 * Each file gets its own IPNS record containing encrypted metadata,
 * while the parent folder only stores a slim FilePointer reference.
 */

/**
 * Decrypted per-file metadata structure.
 * Stored as an encrypted blob in the file's own IPNS record.
 * Encrypted with the parent folder's folderKey (NOT the file's own key).
 */
export type FileMetadata = {
  /** Schema version */
  version: 'v1';
  /** IPFS CID of the encrypted file content */
  cid: string;
  /** Hex-encoded ECIES-wrapped AES-256 key for decrypting file */
  fileKeyEncrypted: string;
  /** Hex-encoded IV used for file encryption */
  fileIv: string;
  /** Original file size in bytes (before encryption) */
  size: number;
  /** MIME type of the original file */
  mimeType: string;
  /** Encryption mode (optional for backward compat; defaults to 'GCM') */
  encryptionMode?: 'GCM' | 'CTR';
  /** Creation timestamp (Unix ms) */
  createdAt: number;
  /** Last modification timestamp (Unix ms) */
  modifiedAt: number;
};

/**
 * Slim file reference stored in v2 folder metadata.
 * Points to a file's own IPNS record instead of embedding all file data inline.
 */
export type FilePointer = {
  type: 'file';
  /** UUID for internal reference */
  id: string;
  /** File name (plaintext, since folder metadata is encrypted) */
  name: string;
  /** IPNS name of the file's own metadata record */
  fileMetaIpnsName: string;
  /** Creation timestamp (Unix ms) */
  createdAt: number;
  /** Last modification timestamp (Unix ms) */
  modifiedAt: number;
};

/**
 * Encrypted file metadata for storage/transmission.
 * Same format as EncryptedFolderMetadata (hex IV + base64 ciphertext).
 */
export type EncryptedFileMetadata = {
  /** Hex-encoded 12-byte IV for AES-GCM */
  iv: string;
  /** Base64-encoded AES-GCM ciphertext (includes 16-byte auth tag) */
  data: string;
};
