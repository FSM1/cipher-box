/**
 * @cipherbox/core
 *
 * CipherBox domain types, metadata schemas, validators, metadata
 * encrypt/decrypt, vault initialization, and IPNS record utilities.
 *
 * This package contains everything that "knows about CipherBox's data model"
 * while @cipherbox/crypto retains only generic cryptographic operations.
 */

// Folder metadata
export {
  encryptFolderMetadata,
  decryptFolderMetadata,
  validateFolderMetadata,
  type FolderMetadata,
  type FolderChild,
  type FolderEntry,
  type EncryptedFolderMetadata,
} from './folder';

// File metadata
export {
  deriveFileIpnsKeypair,
  generateFileIpnsKeypair,
  encryptFileMetadata,
  decryptFileMetadata,
  validateFileMetadata,
  type FileMetadata,
  type FilePointer,
  type EncryptedFileMetadata,
  type VersionEntry,
} from './file';

// Device registry
export {
  encryptRegistry,
  decryptRegistry,
  deriveRegistryIpnsKeypair,
  validateDeviceRegistry,
  type DeviceEntry,
  type DeviceRegistry,
  type DeviceAuthStatus,
  type DevicePlatform,
} from './registry';

// Recycle bin
export {
  encryptBinMetadata,
  decryptBinMetadata,
  deriveBinIpnsKeypair,
  validateBinMetadata,
  type BinEntry,
  type RecycleBinMetadata,
} from './bin';

// Vault init + blob v2 format
export {
  initializeVault,
  encryptVaultKeys,
  decryptVaultKeys,
  serializeVaultBlobV2,
  deserializeVaultBlobV2,
  detectBlobVersion,
  BLOB_V2_VERSION,
  type VaultInit,
  type EncryptedVaultKeys,
  type VaultBlobV2,
} from './vault';

// IPNS records
export {
  createIpnsRecord,
  deriveIpnsName,
  marshalIpnsRecord,
  unmarshalIpnsRecord,
  signIpnsData,
  IPNS_SIGNATURE_PREFIX,
  type IPNSRecord,
} from './ipns';
