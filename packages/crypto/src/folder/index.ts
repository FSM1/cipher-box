/**
 * @cipherbox/crypto - Folder Module
 *
 * Folder metadata types and encryption utilities.
 * Supports both v1 (inline file data) and v2 (per-file IPNS pointer) schemas.
 */

// Types
export type {
  FolderMetadata,
  FolderChild,
  FolderEntry,
  FileEntry,
  EncryptedFolderMetadata,
  FolderMetadataV2,
  FolderChildV2,
  AnyFolderMetadata,
} from './types';

// Encryption functions and validators
export {
  encryptFolderMetadata,
  decryptFolderMetadata,
  isV2Metadata,
  validateFolderMetadata,
} from './metadata';
