/**
 * @cipherbox/crypto - Folder Module
 *
 * Folder metadata types and encryption utilities.
 * v2 schema with per-file IPNS pointers (FilePointer children).
 */

// Types
export type { FolderMetadata, FolderChild, FolderEntry, EncryptedFolderMetadata } from './types';

// Encryption functions and validators
export { encryptFolderMetadata, decryptFolderMetadata, validateFolderMetadata } from './metadata';
