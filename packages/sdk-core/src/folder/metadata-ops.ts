/**
 * Folder metadata operations — child ref mutations on SealedChildRef arrays.
 *
 * Phase 63 implementation: un-stubbed add/move/rename/delete operations on the
 * SealedChildRef children list stored in a folder node's read-body.
 *
 * Design invariants (READ-03, READ-04, D-09):
 *   - addFilePointerToFolder seals the new child readKey under the parent
 *     readKey ONCE via sealChildReadKey (role 0x02). No per-recipient fan-out.
 *   - moveItem is a pure SealedChildRef link rewrite — ZERO re-encryption of the
 *     moved subtree. The existing readKeySealed travels unchanged.
 *   - renameInFolder and deleteFromFolder are pure synchronous array transforms.
 *   - None of these functions zero any key parameter — callers are terminal owners (D-09).
 *   - The parent re-seal (updateFolderMetadataAndPublish) happens AFTER these
 *     transforms, not inside them.
 */

import { sealChildReadKey } from '@cipherbox/core';
import type { SealedChildRef, NodeKind } from '@cipherbox/core';

/**
 * Rename a child entry in a folder's sealed child ref list.
 *
 * Pure synchronous transform — no re-encryption. The name lives inside the
 * sealed parent read-body; the parent re-seal happens in
 * updateFolderMetadataAndPublish.
 *
 * @param params.children - Current SealedChildRef array
 * @param params.childId  - ipnsName of the child to rename
 * @param params.newName  - New display name
 * @returns Updated children array and the renamed ref (original array not mutated)
 */
export function renameInFolder(params: {
  children: SealedChildRef[];
  childId: string;
  newName: string;
}): { updatedChildren: SealedChildRef[]; renamedChild: SealedChildRef } {
  const idx = params.children.findIndex((c) => c.ipnsName === params.childId);
  if (idx === -1) throw new Error('Item not found');
  const renamedChild: SealedChildRef = { ...params.children[idx], name: params.newName };
  const updatedChildren = [
    ...params.children.slice(0, idx),
    renamedChild,
    ...params.children.slice(idx + 1),
  ];
  return { updatedChildren, renamedChild };
}

/**
 * Remove a child entry from a folder's sealed child ref list.
 *
 * Pure synchronous transform — no re-encryption.
 *
 * @param params.children - Current SealedChildRef array
 * @param params.childId  - ipnsName of the child to remove
 * @returns Updated children array and the removed ref
 */
export function deleteFromFolder(params: { children: SealedChildRef[]; childId: string }): {
  updatedChildren: SealedChildRef[];
  removedItem: SealedChildRef;
} {
  const idx = params.children.findIndex((c) => c.ipnsName === params.childId);
  if (idx === -1) throw new Error('Item not found');
  const removedItem = params.children[idx];
  const updatedChildren = params.children.filter((c) => c.ipnsName !== params.childId);
  return { updatedChildren, removedItem };
}

/**
 * Add a child node ref to a folder's sealed child ref list.
 *
 * Seals the child's readKey under the parent readKey ONCE via sealChildReadKey
 * (role 0x02 child-readkey). No per-recipient fan-out — existing grant-holders
 * already hold the parent readKey transitively (READ-03 / SC#3 / §3.4).
 *
 * @param params.children       - Current SealedChildRef array
 * @param params.childReadKey   - 32-byte AES readKey of the new child node
 * @param params.parentReadKey  - 32-byte AES readKey of the parent folder (wrapping key)
 * @param params.childId        - Hyphenated UUID of the child node (AAD binding)
 * @param params.childKind      - NodeKind of the child ('file' | 'folder' | 'root')
 * @param params.childGeneration - Generation of the child node (0 for new nodes)
 * @param params.name           - Display name of the child
 * @param params.ipnsName       - IPNS k51 name of the child node
 * @param params.versionFloor   - Owner-vouched IPNS sequence floor (0n for new nodes)
 * @returns Updated children array and the new SealedChildRef
 *
 * @security Does NOT zero childReadKey or parentReadKey — callers are terminal owners (D-09).
 */
export async function addFilePointerToFolder(params: {
  children: SealedChildRef[];
  childReadKey: Uint8Array;
  parentReadKey: Uint8Array;
  childId: string;
  childKind: NodeKind;
  childGeneration: number;
  name: string;
  ipnsName: string;
  versionFloor: bigint;
}): Promise<{ updatedChildren: SealedChildRef[]; newRef: SealedChildRef }> {
  // Seal child readKey under parent readKey — EXACTLY ONE call, no per-recipient loop
  const readKeySealed = await sealChildReadKey(
    params.childReadKey,
    params.parentReadKey,
    params.childId,
    params.childKind,
    params.childGeneration
  );

  const newRef: SealedChildRef = {
    name: params.name,
    ipnsName: params.ipnsName,
    generation: params.childGeneration,
    versionFloor: params.versionFloor,
    readKeySealed,
  };

  return { updatedChildren: [...params.children, newRef], newRef };
}

/**
 * Move a child entry between two folders' sealed child ref lists.
 *
 * Pure synchronous link rewrite — the SealedChildRef moves AS-IS with ZERO
 * re-encryption of the child's readKey (READ-04 / SC#4 / §3.5). The child's
 * readKeySealed (sealed under the source parent's readKey) is preserved.
 *
 * @param params.sourceChildren - SealedChildRef array of the source folder
 * @param params.destChildren   - SealedChildRef array of the destination folder
 * @param params.childId        - ipnsName of the child to move
 * @returns Updated source + dest arrays and the moved SealedChildRef
 */
export function moveItem(params: {
  sourceChildren: SealedChildRef[];
  destChildren: SealedChildRef[];
  childId: string;
}): { updatedSource: SealedChildRef[]; updatedDest: SealedChildRef[]; movedRef: SealedChildRef } {
  const idx = params.sourceChildren.findIndex((c) => c.ipnsName === params.childId);
  if (idx === -1) throw new Error('Item not found');
  const movedRef = params.sourceChildren[idx];
  const updatedSource = params.sourceChildren.filter((c) => c.ipnsName !== params.childId);
  const updatedDest = [...params.destChildren, movedRef];
  return { updatedSource, updatedDest, movedRef };
}
