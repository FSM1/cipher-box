/**
 * File Metadata Service - Per-file Node operations (stub)
 *
 * @stub phase 65 — all functions require the Node write-chain.
 * The FileMetadata/FilePointer/EncryptedFileMetadata codec is retired (node/v3).
 * Per-file data is now inside NodeContent (sealed in the file Node's read-body)
 * and NodeWriteBody (sealed in the file Node's write-body). Phase 65 will
 * restore file creation, update, and version management using the Node codec.
 */

import type { VersionEntry } from '@cipherbox/core';

/** Record payload ready for batch publish */
export type FileIpnsRecordPayload = {
  ipnsName: string;
  recordBase64: string;
  metadataCid: string;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
};

/** Content fields applied as `updates` when routing a file metadata write through the SDK client. */
export type FileContentUpdates = {
  cid?: string;
  fileKeyEncrypted?: string;
  fileIv?: string;
  size?: number;
  encryptionMode?: 'GCM' | 'CTR';
};

/**
 * Create a per-file Node record.
 * @stub phase 65 — requires Node write-chain (NodeWriteBody sealing)
 */
export async function createFileMetadata(_params: {
  fileId: string;
  cid: string;
  fileKeyEncrypted: string;
  fileIv: string;
  size: number;
  mimeType: string;
  folderKey: Uint8Array;
  userPublicKey: Uint8Array;
  encryptionMode?: 'GCM' | 'CTR';
}): Promise<{
  fileMetaIpnsName: string;
  ipnsRecord: FileIpnsRecordPayload;
  ipnsPrivateKeyEncrypted: string;
}> {
  throw new Error('not implemented — phase 65 (file creation requires Node write-chain)');
}

/**
 * Resolve a file Node's content.
 * @stub phase 63 — requires Node read-chain (NodeContent unsealing)
 */
export async function resolveFileMetadata(
  _fileIpnsName: string,
  _folderKey: Uint8Array
): Promise<{
  metadata: {
    cid: string;
    fileIv: string;
    size: number;
    mimeType: string;
    encryptionMode?: 'GCM' | 'CTR';
    versions?: VersionEntry[];
  };
  metadataCid: string;
}> {
  throw new Error('not implemented — phase 63 (file metadata resolution requires Node read-chain)');
}

/**
 * Determine whether a file content update should create a new version entry.
 * @stub phase 65 — version logic moves to NodeContent.versions
 */
export function shouldCreateVersion(
  _currentVersions: VersionEntry[] | undefined,
  _forceVersion: boolean
): boolean {
  throw new Error('not implemented — phase 65 (version check requires NodeContent.versions)');
}

/**
 * Update an existing file Node.
 * @stub phase 65 — requires Node write-chain
 */
export async function updateFileMetadata(_params: {
  fileIpnsPrivateKey: Uint8Array;
  fileMetaIpnsName: string;
  folderKey: Uint8Array;
  updates: FileContentUpdates;
  currentVersions?: VersionEntry[];
  createVersion: boolean;
}): Promise<{
  ipnsRecord: FileIpnsRecordPayload;
  prunedCids: string[];
}> {
  throw new Error('not implemented — phase 65 (file update requires Node write-chain)');
}

/**
 * Compute the metadata transform for restoring a previous version (pure, no publish).
 * @stub phase 65 — requires NodeContent.versions
 */
export function computeRestoreVersionUpdate(
  _versions: VersionEntry[],
  _versionIndex: number
): { updates: FileContentUpdates; retainedVersions: VersionEntry[]; prunedCids: string[] } {
  throw new Error('not implemented — phase 65 (version restore requires NodeContent.versions)');
}

/**
 * Compute the metadata transform for deleting a past version (pure, no publish).
 * @stub phase 65 — requires NodeContent.versions
 */
export function computeDeleteVersionUpdate(
  _versions: VersionEntry[],
  _versionIndex: number
): { retainedVersions: VersionEntry[]; deletedCid: string } {
  throw new Error('not implemented — phase 65 (version delete requires NodeContent.versions)');
}
