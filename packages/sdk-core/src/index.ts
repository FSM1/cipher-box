// Errors
export { ConflictError, isConflictExhausted, is409 } from './errors';

// CAS publish helper
export { publishWithCas } from './cas';

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
  mergeChildren,
} from './folder';

// Tree traversal utilities
export { getDepth, calculateSubtreeDepth, isDescendantOf, type TreeNode } from './folder';

// File metadata operations
export {
  createFileMetadata,
  resolveFileMetadata,
  updateFileMetadata,
  downloadFileContent,
  type FileIpnsRecordPayload,
  type UpdateFileContentParams,
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
export { publishVaultKeyBlob, loadVaultKeyBlob, publishEmptyRootNode } from './vault';

// Share operations (read-chain navigation + grant issuance)
export {
  navigateReadChain,
  type NavigateResult,
  issueReadGrant,
  claimInviteReadKey,
  type ReadGrantPayload,
} from './share';

// Rotation engine + scope-exit predicate
export {
  rotateReadFromNode,
  rotateOne,
  mintFileKeyOnRotate,
  reMintGrantsRootedAt,
  mergeConcurrentChildren,
  verifySubtreeClean,
  rotateWriteFromNode,
  RootKeyStaleError,
  type RotationJobRecord,
  type RotationStatus,
  type RotationParams,
  type RotateReadResult,
  type WriteRevocationCallbacks,
  type GrantRemintCallbacks,
  type DirtyFrontierItem,
  hasCoveringGrant,
  maybeRotateOnScopeExit,
  type CoverageParams,
  type ScopeExitResult,
  type ScopeExitDeps,
} from './rotation';

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
