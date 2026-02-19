/**
 * @cipherbox/crypto - File Module
 *
 * Per-file IPNS metadata types, derivation, and encryption utilities.
 */

// Types
export type { FileMetadata, FilePointer, EncryptedFileMetadata } from './types';

// IPNS keypair derivation
export { deriveFileIpnsKeypair } from './derive-ipns';

// Metadata encryption functions
export { encryptFileMetadata, decryptFileMetadata, validateFileMetadata } from './metadata';
