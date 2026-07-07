/**
 * Rotation children merge — three-way merge of SealedChildRef arrays, LOCAL WINS.
 *
 * ROTATION-ONLY. NEVER use this for non-rotation folder mutations — see
 * `folder/merge.ts`'s `mergeChildren` for the generic (remote-wins) policy.
 * `mergeRotatedChildren` is a wholly separate function, not a flag on
 * `mergeChildren`, so the local-wins policy is syntactically impossible to
 * invoke from a non-rotation call site (closes the merge-downgrade
 * Elevation-of-Privilege gap, T-70-01).
 *
 * Semantics (design §4.5 step 5, SC#1 / T-70-01):
 *   - Local wins on conflict: a rotated child present in local under the new
 *     read-key seal survives a CAS-409 re-merge even when remote still holds
 *     the pre-rotation seal — this preserves the rotation's D-02 re-seal so
 *     an authorized reader stays navigable and a revoked reader's old-key
 *     seal is never re-adopted.
 *   - Remote-only (not-in-base) entries are concurrent adds: included, still
 *     under their pre-rotation seal. A full re-key of these entries under the
 *     new epoch is a follow-on concern (design §4.5 step 5), not handled by
 *     this merge.
 *   - Base-only (not in local AND not in remote) entries are intentional
 *     deletes: dropped.
 *
 * Known accepted residual (T-70-02, low severity, self-healing — do NOT
 * "fix" here): because local unconditionally wins, a child present in both
 * base and local but concurrently deleted on remote (a delete that raced the
 * rotation's CAS) is resurrected rather than pruned. This is an accepted
 * design boundary — the delete's own later CAS retry, or the next owner
 * mutation, self-heals it.
 */

import type { SealedChildRef } from '@cipherbox/core';

/**
 * Rotation-only three-way merge of SealedChildRef arrays.
 *
 * @param base   The children list at the time the local (rotation) publish was prepared (CAS base snapshot).
 * @param local  The local children list produced by the rotation walk — carries the new-key re-seal.
 * @param remote The remote (winning) children list fetched after the 409 conflict.
 * @returns      Merged SealedChildRef[] — local wins on conflict, remote-only
 *               concurrent adds are included, base-only intentional deletes
 *               are dropped.
 */
export function mergeRotatedChildren(
  base: SealedChildRef[],
  local: SealedChildRef[],
  remote: SealedChildRef[]
): SealedChildRef[] {
  const baseNames = new Set(base.map((c) => c.ipnsName));
  const merged = new Map<string, SealedChildRef>();

  // Concurrent adds: remote entries not present at the base snapshot.
  for (const child of remote) {
    if (!baseNames.has(child.ipnsName)) merged.set(child.ipnsName, child);
  }

  // Local wins: insert local last so it overrides any remote entry on
  // conflict. NOTE (T-70-02 accepted residual): this unconditionally
  // re-adds any base+local entry even when remote has concurrently deleted
  // it — a known, self-healing tradeoff, not a bug to close in this merge.
  for (const child of local) {
    merged.set(child.ipnsName, child);
  }

  return Array.from(merged.values());
}
