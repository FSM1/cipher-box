/**
 * Folder metadata operations - pure transforms on folder children arrays.
 * No IPFS/IPNS side effects; returns updated data for caller to publish.
 */

import type { FolderChild, FilePointer } from '@cipherbox/core';

/**
 * Rename a child entry (folder or file) in folder metadata.
 *
 * Pure metadata operation: returns updated children array without publishing.
 */
export function renameInFolder(params: {
  children: FolderChild[];
  childId: string;
  newName: string;
}): { updatedChildren: FolderChild[]; renamedChild: FolderChild } {
  const children = [...params.children];
  const index = children.findIndex((c) => c.id === params.childId);

  if (index === -1) throw new Error('Item not found');

  const nameExists = children.some((c) => c.name === params.newName && c.id !== params.childId);
  if (nameExists) throw new Error('An item with this name already exists');

  const renamedChild = {
    ...children[index],
    name: params.newName,
    modifiedAt: Date.now(),
  };
  children[index] = renamedChild;

  return { updatedChildren: children, renamedChild };
}

/**
 * Remove a child entry (folder or file) from folder metadata.
 *
 * Pure metadata operation: returns updated children array and the removed item.
 */
export function deleteFromFolder(params: { children: FolderChild[]; childId: string }): {
  updatedChildren: FolderChild[];
  removedItem: FolderChild;
} {
  const index = params.children.findIndex((c) => c.id === params.childId);
  if (index === -1) throw new Error('Item not found');

  const removedItem = params.children[index];
  const updatedChildren = params.children.filter((c) => c.id !== params.childId);

  return { updatedChildren, removedItem };
}

/**
 * Add a file pointer to folder children.
 *
 * Pure metadata operation: returns updated children array with the new file pointer.
 */
export function addFilePointerToFolder(params: {
  children: FolderChild[];
  fileId: string;
  fileName: string;
  fileMetaIpnsName: string;
  ipnsPrivateKeyEncrypted: string;
}): { updatedChildren: FolderChild[]; filePointer: FilePointer } {
  const nameExists = params.children.some((c) => c.name === params.fileName);
  if (nameExists) throw new Error('A file with this name already exists');

  const now = Date.now();
  const filePointer: FilePointer = {
    type: 'file',
    id: params.fileId,
    name: params.fileName,
    fileMetaIpnsName: params.fileMetaIpnsName,
    ipnsPrivateKeyEncrypted: params.ipnsPrivateKeyEncrypted,
    createdAt: now,
    modifiedAt: now,
  };

  return {
    updatedChildren: [...params.children, filePointer],
    filePointer,
  };
}

/**
 * Move a child entry between folders.
 *
 * Pure metadata operation: returns updated source and dest children arrays.
 * Uses add-before-remove pattern conceptually (caller publishes dest first, then source).
 */
export function moveItem(params: {
  sourceChildren: FolderChild[];
  destChildren: FolderChild[];
  childId: string;
}): {
  updatedSourceChildren: FolderChild[];
  updatedDestChildren: FolderChild[];
  movedItem: FolderChild;
} {
  const index = params.sourceChildren.findIndex((c) => c.id === params.childId);
  if (index === -1) throw new Error('Item not found');

  const movedItem = {
    ...params.sourceChildren[index],
    modifiedAt: Date.now(),
  };

  // Check name collision in destination
  const nameExists = params.destChildren.some((c) => c.name === movedItem.name);
  if (nameExists) {
    throw new Error('An item with this name already exists in destination');
  }

  const updatedSourceChildren = params.sourceChildren.filter((c) => c.id !== params.childId);
  const updatedDestChildren = [...params.destChildren, movedItem];

  return { updatedSourceChildren, updatedDestChildren, movedItem };
}
