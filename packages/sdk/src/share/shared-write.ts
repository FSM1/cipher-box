/**
 * @cipherbox/sdk - Shared-write operations
 *
 * PHASE 62 STUB: All write operations on shared folders require the node/v3
 * write-chain (structured write-body, role 0x04) and the share fan-out redesign,
 * both owned by phase 65. All exported functions throw
 * 'not implemented — phase 65 (write-chain)' until that phase rewires them.
 *
 * The original implementation is preserved in the quarantined test suite
 * (shared-write.test.ts, client-shared-write.test.ts — TODO phase 65) as the
 * spec the owning phase revives.
 *
 * addShareKeys/reWrapForRecipients: the share fan-out is being redesigned for the
 * read-keychaining model (phase 63 for read fan-out, phase 65 for write fan-out).
 * Call sites that added share_keys entries are stubbed here and quarantined.
 */

import type { SdkContext } from '@cipherbox/sdk-core';
import type { SealedChildRef } from '@cipherbox/core';
import type { ShareKeyEntryDtoKeyType } from '@cipherbox/api-client';

/** Re-export the canonical share key type for consumers */
export type ShareKeyType = ShareKeyEntryDtoKeyType;

/**
 * Context for shared-write operations on a folder.
 * Provides all state needed to modify folder contents and publish changes.
 */
export type SharedWriteContext = {
  /** SDK context for IPFS/IPNS API access */
  ctx: SdkContext;
  /** Decrypted AES-256 folder key for the current folder */
  folderKey: Uint8Array;
  /** Ed25519 private key for signing IPNS publishes */
  ipnsPrivateKey: Uint8Array;
  /** IPNS name of the current folder */
  ipnsName: string;
  /** Current sequence number for conflict detection */
  sequenceNumber: bigint;
  /** Current folder children (sealed child refs — phase 65 rewires the write-chain) */
  children: SealedChildRef[];
  /** Sharer's secp256k1 public key */
  ownerPublicKey: Uint8Array;
  /** Current user's secp256k1 public key */
  recipientPublicKey: Uint8Array;
  /** Share ID for addShareKeysFn calls */
  shareId: string;
  /**
   * Callback to add share keys for the recipient.
   * @stub phase 65 — share fan-out redesign (addShareKeys removed in write-chain model)
   */
  addShareKeysFn: (
    shareId: string,
    keys: Array<{
      keyType: ShareKeyType;
      itemId: string;
      encryptedKey: string;
    }>
  ) => Promise<void>;
};

// ---------------------------------------------------------------------------
// Stubs — all write operations require phase 65 write-chain
// ---------------------------------------------------------------------------

/**
 * Upload a file to a write-shared folder.
 * @stub phase 65 (write-chain)
 */
export async function uploadToSharedFolder(
  swCtx: SharedWriteContext,
  params: { data: Uint8Array; fileName: string; mimeType?: string }
): Promise<{
  publishedChildren: SealedChildRef[];
  newSequenceNumber: bigint;
  filePointer: SealedChildRef;
}> {
  void swCtx;
  void params;
  throw new Error('not implemented — phase 65 (write-chain)');
}

/**
 * Create a subfolder in a write-shared folder.
 * @stub phase 65 (write-chain)
 */
export async function createSharedSubfolder(
  swCtx: SharedWriteContext,
  params: { name: string }
): Promise<{
  publishedChildren: SealedChildRef[];
  newSequenceNumber: bigint;
  folderEntry: SealedChildRef;
}> {
  void swCtx;
  void params;
  throw new Error('not implemented — phase 65 (write-chain)');
}

/**
 * Rename an item in a write-shared folder.
 * @stub phase 65 (write-chain)
 */
export async function renameInSharedFolder(
  swCtx: SharedWriteContext,
  params: { itemId: string; newName: string }
): Promise<{
  publishedChildren: SealedChildRef[];
  newSequenceNumber: bigint;
}> {
  void swCtx;
  void params;
  throw new Error('not implemented — phase 65 (write-chain)');
}

/**
 * Delete an item from a write-shared folder.
 * @stub phase 65 (write-chain)
 */
export async function deleteFromSharedFolder(
  swCtx: SharedWriteContext,
  params: { itemId: string }
): Promise<{
  publishedChildren: SealedChildRef[];
  newSequenceNumber: bigint;
}> {
  void swCtx;
  void params;
  throw new Error('not implemented — phase 65 (write-chain)');
}

/**
 * Update a file's content in a write-shared context.
 * @stub phase 65 (write-chain)
 */
export async function updateSharedFile(params: {
  ctx: SdkContext;
  folderKey: Uint8Array;
  ownerPublicKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  shareId: string;
  addShareKeysFn: (
    shareId: string,
    keys: Array<{
      keyType: ShareKeyType;
      itemId: string;
      encryptedKey: string;
    }>
  ) => Promise<void>;
  filePointer: SealedChildRef;
  newContent: Uint8Array;
  getFileIpnsKeyFn: (itemId: string) => Promise<Uint8Array | null>;
}): Promise<void> {
  void params;
  throw new Error('not implemented — phase 65 (write-chain)');
}

/**
 * Move an item between two subfolders within a single shared folder.
 * @stub phase 65 (write-chain)
 */
export async function moveInSharedFolder(params: {
  ctx: SdkContext;
  srcCtx: {
    folderKey: Uint8Array;
    ipnsPrivateKey: Uint8Array;
    ipnsName: string;
    sequenceNumber: bigint;
    children: SealedChildRef[];
  };
  destCtx: {
    folderKey: Uint8Array;
    ipnsPrivateKey: Uint8Array;
    ipnsName: string;
    sequenceNumber: bigint;
    children: SealedChildRef[];
  };
  itemId: string;
  fileIpnsPrivateKey: Uint8Array | null;
}): Promise<{
  srcResult: { publishedChildren: SealedChildRef[]; newSequenceNumber: bigint };
  destResult: { publishedChildren: SealedChildRef[]; newSequenceNumber: bigint };
}> {
  void params;
  throw new Error('not implemented — phase 65 (write-chain)');
}

/**
 * Update a share's permission level.
 *
 * Thin callback wrapper — no key material involved.
 */
export async function updateSharePermission(params: {
  shareId: string;
  permission: string;
  encryptedIpnsKey?: string;
  updatePermissionFn: (
    shareId: string,
    body: { permission: string; encryptedIpnsKey?: string }
  ) => Promise<void>;
}): Promise<void> {
  await params.updatePermissionFn(params.shareId, {
    permission: params.permission,
    encryptedIpnsKey: params.encryptedIpnsKey,
  });
}
