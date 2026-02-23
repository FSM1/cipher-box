/**
 * @cipherbox/crypto - File Module
 *
 * Per-file IPNS metadata types, derivation, and encryption utilities.
 */

// Types
export type { FileMetadata, FilePointer, EncryptedFileMetadata, VersionEntry } from './types';

// IPNS keypair derivation / generation
export { deriveFileIpnsKeypair, generateFileIpnsKeypair } from './derive-ipns';

// Metadata encryption functions
export { encryptFileMetadata, decryptFileMetadata, validateFileMetadata } from './metadata';
