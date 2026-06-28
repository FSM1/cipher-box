/**
 * Shared key-wrapping utilities for ECIES re-wrapping operations.
 *
 * @stub phase 65 — all tree-traversal key collection requires the Node read-chain.
 * The FolderChild/FolderEntry/FilePointer types are retired (node/v3); the
 * descendent keys (folder readKey, file fileKey, IPNS signing keys) are now
 * sealed inside Node read-bodies and write-bodies. Phase 65 will restore
 * collectChildKeys using SealedChildRef + Node unsealing to traverse subtrees
 * and re-wrap keys for a target public key.
 */

import type { SealedChildRef } from '@cipherbox/core';
import type { ChildKeyDto } from '@cipherbox/api-client';

/**
 * Collect all descendant keys from a folder for sharing.
 *
 * @stub phase 65 — requires Node read-chain (SealedChildRef unsealing) +
 * write-chain (IPNS signing key distribution)
 */
export async function collectChildKeys(
  _children: SealedChildRef[],
  _folderKey: Uint8Array,
  _ownerPrivateKey: Uint8Array,
  _targetPubKeyBytes: Uint8Array,
  _permission: 'read' | 'write',
  _onProgress: (wrapped: number) => void
): Promise<ChildKeyDto[]> {
  throw new Error(
    'not implemented — phase 65 (key collection requires Node read-chain + write-chain)'
  );
}
