/**
 * Folder metadata operations — child ref mutations on SealedChildRef arrays.
 *
 * Phase 62 stub: every operation that mutates a folder's child list requires sealing
 * child readKeys under the parent readKey (phase 63) or re-sealing after a CAS merge
 * (phase 64). All functions throw 'not implemented — phase 63' until that phase
 * rewires them with the write-chain sealing logic.
 *
 * The original pure-transform logic for FolderChild[] (FolderEntry | FilePointer) is
 * preserved in the quarantined test suite (folder.test.ts, TODO phase 63) as the
 * spec the owning phase revives.
 */

import type { SealedChildRef } from '@cipherbox/core';

/**
 * Rename a child entry in a folder's sealed child ref list.
 *
 * @stub phase 63 — will re-seal the updated child ref under the parent readKey.
 */
export function renameInFolder(params: {
  children: SealedChildRef[];
  childId: string;
  newName: string;
}): never {
  void params;
  throw new Error('not implemented — phase 63 (write-chain child ref mutation)');
}

/**
 * Remove a child entry from a folder's sealed child ref list.
 *
 * @stub phase 63 — will re-seal the updated child list under the parent readKey.
 */
export function deleteFromFolder(params: { children: SealedChildRef[]; childId: string }): never {
  void params;
  throw new Error('not implemented — phase 63 (write-chain child ref mutation)');
}

/**
 * Add a file node ref to a folder's sealed child ref list.
 *
 * @stub phase 63 — will seal the new child readKey under the parent readKey
 * and re-seal the updated read-body.
 */
export function addFilePointerToFolder(params: {
  children: SealedChildRef[];
  fileId: string;
  fileName: string;
  fileMetaIpnsName: string;
  ipnsPrivateKeyEncrypted: string;
}): never {
  void params;
  throw new Error('not implemented — phase 63 (add file node + seal child readKey under parent)');
}

/**
 * Move a child entry between two folders' sealed child ref lists.
 *
 * @stub phase 63 — will re-seal the child readKey under the destination parent's readKey.
 */
export function moveItem(params: {
  sourceChildren: SealedChildRef[];
  destChildren: SealedChildRef[];
  childId: string;
}): never {
  void params;
  throw new Error(
    'not implemented — phase 63 (move node + re-seal child readKey under dest parent)'
  );
}
