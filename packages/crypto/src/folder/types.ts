/**
 * @cipherbox/crypto - Folder Metadata Types
 *
 * Type definitions for encrypted folder metadata stored in IPNS records.
 * v2 schema with per-file IPNS pointers (FilePointer children).
 */

import type { FilePointer } from '../file/types';

/**
 * Decrypted folder metadata structure (v2).
 * The entire FolderMetadata object is encrypted as a single blob with AES-256-GCM.
 * Children are FolderEntry (subfolders) or FilePointer (slim IPNS references).
 */
export type FolderMetadata = {
  /** Schema version */
  version: 'v2';
  /** Folders and file pointers in this folder */
  children: FolderChild[];
};

/**
 * A child entry can be either a folder or a file pointer.
 */
export type FolderChild = FolderEntry | FilePointer;

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
 * Encrypted folder metadata for storage/transmission.
 * This is what gets uploaded to IPFS and referenced by IPNS.
 */
export type EncryptedFolderMetadata = {
  /** Hex-encoded 12-byte IV for AES-GCM */
  iv: string;
  /** Base64-encoded AES-GCM ciphertext (includes 16-byte auth tag) */
  data: string;
};
