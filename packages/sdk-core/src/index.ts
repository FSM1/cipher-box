// Types
export type {
  SdkContext,
  TeeKeys,
  IpfsAddResult,
  ProgressCallback,
  DownloadProgressCallback,
} from './types';

// IPFS operations
export { addToIpfs, fetchFromIpfs, unpinFromIpfs, registerCid } from './ipfs';

// IPNS operations
export {
  createAndPublishIpnsRecord,
  batchPublishIpnsRecords,
  resolveIpnsRecord,
  verifyIpnsSignature,
} from './ipns';

// Folder operations
export {
  fetchAndDecryptMetadata,
  loadFolderMetadata,
  createSubfolder,
  updateFolderMetadataAndPublish,
  renameInFolder,
  deleteFromFolder,
  addFilePointerToFolder,
  moveItem,
} from './folder';

// Tree traversal utilities
export { getDepth, calculateSubtreeDepth, isDescendantOf, type TreeNode } from './folder';

// File metadata operations
export {
  createFileMetadata,
  resolveFileMetadata,
  updateFileMetadata,
  type FileIpnsRecordPayload,
} from './file';

// Upload operations
export { uploadFile, type UploadResult, type ExternalEncryptFn } from './upload';

// Encryption mode selection
export {
  selectEncryptionMode,
  normalizeEncryptionMode,
  type EncryptionMode,
} from './encryption-mode';

// Download operations
export { downloadAndDecrypt } from './download';

// Vault key blob operations
export { publishVaultKeyBlob, loadVaultKeyBlob } from './vault';

// Pinning providers (BYO-IPFS)
export {
  type PinningProvider,
  type PinResult,
  type PinStatus,
  type PinningMode,
  type ExternalProviderConfig,
  type ConnectionTestResult,
  type ProviderOptions,
  KuboProvider,
  PsaProvider,
  PinataProvider,
  DualPinProvider,
  testConnection,
  type DualPinResult,
} from './pinning';
