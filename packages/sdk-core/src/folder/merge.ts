import { type FolderChild } from '@cipherbox/core';

/**
 * Three-way merge of FolderChild arrays.
 *
 * Implements the D-01/D-02 merge semantics:
 *
 * - local-add (in local, not base, not remote): kept
 * - remote-add (in remote, not base, not local): kept
 * - added-by-both (in local AND remote, not base): last-write-wins by modifiedAt (>= prefers local)
 * - local-delete, remote-unchanged: dropped
 * - local-delete, remote-edited-after-base: edit-beats-delete, remote version kept
 * - remote-delete, local-kept: local version kept
 * - modified-in-both: last-write-wins by modifiedAt (>= prefers local on tie)
 * - empty/undefined base (D-02 fallback): union of local ∪ remote keyed by id, no deletions
 *
 * All children are keyed by `c.id` (UUID — stable identity).
 * Missing/undefined modifiedAt is treated as 0 for ordering.
 * Input arrays are not mutated.
 */
export function mergeChildren(
  base: FolderChild[],
  local: FolderChild[],
  remote: FolderChild[]
): FolderChild[] {
  const baseById = new Map(base.map((c) => [c.id, c]));
  const localById = new Map(local.map((c) => [c.id, c]));
  const remoteById = new Map(remote.map((c) => [c.id, c]));

  const allIds = new Set([...localById.keys(), ...remoteById.keys()]);
  const merged: FolderChild[] = [];

  for (const id of allIds) {
    const b = baseById.get(id);
    const l = localById.get(id);
    const r = remoteById.get(id);

    if (l && !r && !b) {
      // local-add
      merged.push(l);
    } else if (!l && r && !b) {
      // remote-add
      merged.push(r);
    } else if (l && r && !b) {
      // added-by-both: last-write-wins, >= prefers local on tie
      merged.push((l.modifiedAt ?? 0) >= (r.modifiedAt ?? 0) ? l : r);
    } else if (!l && b) {
      // local-delete: keep remote only if remote was edited after base (edit-beats-delete)
      if (r && (r.modifiedAt ?? 0) > (b.modifiedAt ?? 0)) {
        merged.push(r);
      }
      // otherwise drop (local delete wins)
    } else if (!r && b) {
      // remote-delete: local version wins
      if (l) {
        merged.push(l);
      }
    } else if (l && r) {
      // modified-in-both (b may or may not exist): last-write-wins, >= prefers local on tie
      merged.push((l.modifiedAt ?? 0) >= (r.modifiedAt ?? 0) ? l : r);
    }
  }

  return merged;
}
