/**
 * Folder children merge — three-way merge of SealedChildRef arrays.
 *
 * Phase 62 stub: merging sealed child refs after a CAS conflict is owned by phase 64
 * (HIGH-4 re-merge on conflict). The body throws until phase 64 rewires it.
 *
 * The original merge logic for FolderChild[] (renamed FolderEntry | FilePointer) is
 * preserved in the quarantined test suite (folder-merge.test.ts, TODO phase 64)
 * as the spec the owning phase revives.
 */

import type { SealedChildRef } from '@cipherbox/core';

/**
 * Three-way merge of SealedChildRef arrays.
 *
 * @stub phase 64 — will implement three-way merge semantics for sealed child refs.
 */
export function mergeChildren(
  base: SealedChildRef[],
  local: SealedChildRef[],
  remote: SealedChildRef[]
): never {
  void base;
  void local;
  void remote;
  throw new Error('not implemented — phase 64 (CAS merge on sealed child refs)');
}
