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
  type DeviceRegistryVersion,
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

// Vault init + key blob v3 format + vault settings
export {
  initializeVault,
  encryptVaultKeys,
  decryptVaultKeys,
  serializeVaultBlobV3,
  deserializeVaultBlobV3,
  BLOB_V3_VERSION,
  DEFAULT_VAULT_SETTINGS,
  validateVaultSettings,
  type VaultInit,
  type EncryptedVaultKeys,
  type ByoIpfsConfig,
  type VaultSettings,
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
