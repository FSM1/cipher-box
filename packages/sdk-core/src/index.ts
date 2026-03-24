// Types
export type {
  SdkContext,
  TeeKeys,
  IpfsAddResult,
  ProgressCallback,
  DownloadProgressCallback,
} from './types';

// IPFS operations
export { addToIpfs, fetchFromIpfs, unpinFromIpfs } from './ipfs';

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

// File metadata operations
export {
  createFileMetadata,
  resolveFileMetadata,
  updateFileMetadata,
  type FileIpnsRecordPayload,
} from './file';

// Upload operations
export { uploadFile, type UploadResult } from './upload';

// Download operations
export { downloadAndDecrypt } from './download';

// Pinning providers (BYO-IPFS)
export {
  type PinningProvider,
  type PinResult,
  type PinStatus,
  type PinningMode,
  type ExternalProviderConfig,
  type ConnectionTestResult,
  KuboProvider,
  PsaProvider,
  DualPinProvider,
  testConnection,
  type DualPinResult,
} from './pinning';
