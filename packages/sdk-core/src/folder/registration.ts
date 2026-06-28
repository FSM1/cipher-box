/**
 * Folder registration operations — IPNS record build and batch-publish.
 *
 * Phase 62 stub: all operations that build or update folder IPNS records require the
 * node/v3 seal-child-under-parent write-chain (phase 63) or file node integration
 * (phase 65). All functions throw 'not implemented — phase NN' until those phases
 * rewire them.
 *
 * The original implementation for FolderMetadata (FolderEntry / FolderChild / FilePointer)
 * is preserved in the quarantined test suite (folder.test.ts, TODO phase 63) as the
 * spec the owning phase revives.
 */

import type { Node, SealedChildRef } from '@cipherbox/core';
import type { SdkContext, TeeKeys } from '../types';
import type { FileIpnsRecordPayload } from '../file';

/**
 * Create a new subfolder with generated keys.
 *
 * @stub phase 63 — will generate node IPNS keypair + readKey/writeKey, seal as a
 * SealedChildRef under the parent readKey, and return a Node payload.
 */
export async function createSubfolder(params: {
  name: string;
  userPublicKey: Uint8Array;
  teeKeys?: TeeKeys;
}): Promise<{
  node: Node;
  ipnsPrivateKey: Uint8Array;
  rootReadKey: Uint8Array;
  rootWriteKey: Uint8Array;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
}> {
  void params;
  throw new Error('not implemented — phase 63 (create subfolder node + seal readKey under parent)');
}

/**
 * Update folder metadata and publish to IPNS.
 *
 * @stub phase 63 — will seal the updated Node read-body + write-body, then publish the
 * new PublishedNode to the folder's IPNS name.
 */
export async function updateFolderMetadataAndPublish(params: {
  children: SealedChildRef[];
  baseChildren?: SealedChildRef[];
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsPublicKey?: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  ctx: SdkContext;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
}): Promise<{ cid: string; newSequenceNumber: bigint; publishedChildren: SealedChildRef[] }> {
  void params;
  throw new Error('not implemented — phase 63 (seal updated Node + publish to IPNS)');
}

/**
 * Add a single file to a folder and batch-publish both IPNS records.
 *
 * @stub phase 65 — will create a file Node, seal its readKey under the parent folder
 * readKey as a SealedChildRef, and batch-publish both IPNS records.
 */
export async function addFileToFolder(params: {
  children: SealedChildRef[];
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsPublicKey?: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  fileId: string;
  name: string;
  fileIpnsRecord: FileIpnsRecordPayload;
  ipnsPrivateKeyEncrypted: string;
  ctx: SdkContext;
}): Promise<{ fileNode: Node; newSequenceNumber: bigint }> {
  void params;
  throw new Error(
    'not implemented — phase 65 (add file Node + seal child readKey + batch-publish)'
  );
}

/**
 * Add multiple files to a folder and batch-publish all IPNS records.
 *
 * @stub phase 65 — will create file Nodes, seal their readKeys under the parent folder
 * readKey, and batch-publish all records in a single API call.
 */
export async function addFilesToFolder(params: {
  children: SealedChildRef[];
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsPublicKey?: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  files: Array<{
    fileId: string;
    name: string;
    fileIpnsRecord: FileIpnsRecordPayload;
    ipnsPrivateKeyEncrypted: string;
  }>;
  ctx: SdkContext;
}): Promise<{ fileNodes: Node[]; newSequenceNumber: bigint }> {
  void params;
  throw new Error(
    'not implemented — phase 65 (add file Nodes + seal child readKeys + batch-publish)'
  );
}

/**
 * Replace file content in folder (content update — folder IPNS record unchanged).
 *
 * @stub phase 65 — will publish only the file Node IPNS record; folder is untouched
 * because the SealedChildRef still points to the same file IPNS name.
 */
export async function replaceFileInFolder(params: {
  children: SealedChildRef[];
  fileId: string;
  fileIpnsRecord: FileIpnsRecordPayload;
  ctx: SdkContext;
}): Promise<void> {
  void params;
  throw new Error('not implemented — phase 65 (replace file Node content + publish file IPNS)');
}
