/**
 * @cipherbox/crypto - Folder Metadata Types
 *
 * Type definitions for encrypted folder metadata stored in IPNS records.
 * Supports both v1 (inline file data) and v2 (per-file IPNS pointer) schemas.
 */

import type { FilePointer } from '../file/types';

/**
 * Decrypted folder metadata structure.
 * The entire FolderMetadata object is encrypted as a single blob with AES-256-GCM.
 */
export type FolderMetadata = {
  /** Schema version for future migrations */
  version: 'v1';
  /** Files and subfolders in this folder */
  children: FolderChild[];
};

/**
 * A child entry can be either a folder or a file.
 */
export type FolderChild = FolderEntry | FileEntry;

/**
 * Subfolder entry within folder metadata.
 * Contains ECIES-wrapped keys for accessing the subfolder.
 */
export type FolderEntry = {
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
export type FileEntry = {
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
 * v2 folder metadata with per-file IPNS pointers instead of inline file data.
 * Children can be FolderEntry (unchanged) or FilePointer (slim IPNS reference).
 */
export type FolderMetadataV2 = {
  /** Schema version for v2 format */
  version: 'v2';
  /** Folders and file pointers in this folder */
  children: FolderChildV2[];
};

/**
 * A v2 child entry can be either a folder or a file pointer.
 */
export type FolderChildV2 = FolderEntry | FilePointer;

/**
 * Union type for validation - accepts both v1 and v2 folder metadata.
 */
export type AnyFolderMetadata = FolderMetadata | FolderMetadataV2;

/**
 * Encrypted folder metadata for storage/transmission.
 * This is what gets uploaded to IPFS and referenced by IPNS.
 */
export type EncryptedFolderMetadata = {
  /** Hex-encoded 12-byte IV for AES-GCM */
  iv: string;
  /** Base64-encoded AES-GCM ciphertext (includes 16-byte auth tag) */
  data: string;
};
