/**
 * @cipherbox/crypto - Folder Module
 *
 * Folder metadata types and encryption utilities.
 */

// Types
export type {
  FolderMetadata,
  FolderChild,
  FolderEntry,
  FileEntry,
  EncryptedFolderMetadata,
} from './types';

// Encryption functions
export { encryptFolderMetadata, decryptFolderMetadata } from './metadata';
