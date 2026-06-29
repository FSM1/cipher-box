/**
 * Folder children merge — three-way merge of SealedChildRef arrays.
 *
 * Semantics (design §3.7 / §4.6 — ROT-05/HIGH-4):
 *   - Union by ipnsName: local entries loaded first, remote entries overwrite on conflict.
 *   - Remote wins: a concurrent add present only in remote is never dropped.
 *   - Intentional delete: a base entry absent from BOTH local AND remote is pruned.
 *   - One-sided delete: a base entry absent from only one side is kept (union wins).
 *   - No crypto: operates purely on already-sealed SealedChildRef objects.
 */

import type { SealedChildRef } from '@cipherbox/core';

/**
 * Three-way merge of SealedChildRef arrays.
 *
 * @param base   The children list at the time the local publish was prepared (CAS base snapshot).
 * @param local  The local (stale) children list that lost the CAS race.
 * @param remote The remote (winning) children list fetched after the 409 conflict.
 * @returns      Merged SealedChildRef[] — union by ipnsName, remote wins on conflict,
 *               intentional deletes (absent from both sides) are honoured.
 */
export function mergeChildren(
  base: SealedChildRef[],
  local: SealedChildRef[],
  remote: SealedChildRef[]
): SealedChildRef[] {
  // Build a name-keyed map: local first, remote overwrites (remote wins on conflict).
  const merged = new Map<string, SealedChildRef>();
  for (const child of local) {
    merged.set(child.ipnsName, child);
  }
  for (const child of remote) {
    merged.set(child.ipnsName, child);
  }

  // Prune intentional deletes: a base entry absent from BOTH local AND remote.
  const localNames = new Set(local.map((c) => c.ipnsName));
  const remoteNames = new Set(remote.map((c) => c.ipnsName));
  for (const child of base) {
    if (!localNames.has(child.ipnsName) && !remoteNames.has(child.ipnsName)) {
      merged.delete(child.ipnsName);
    }
  }

  return Array.from(merged.values());
}
