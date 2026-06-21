/**
 * Folder operations - Stateless folder CRUD with encryption
 *
 * Extracted from: apps/web/src/services/folder.service.ts
 * All store access replaced with explicit parameters.
 * Functions take metadata in, return updated metadata out.
 */

// Tree traversal utilities
export { getDepth, calculateSubtreeDepth, isDescendantOf, type TreeNode } from './tree';
export { mergeChildren } from './merge';

// Load operations (fetch + decrypt from IPFS/IPNS)
export * from './load';

// Pure metadata transforms (rename, delete, add, move — no network side effects)
export * from './metadata-ops';

// IPNS record build + batch-publish (createSubfolder, updateFolderMetadataAndPublish, etc.)
export * from './registration';
