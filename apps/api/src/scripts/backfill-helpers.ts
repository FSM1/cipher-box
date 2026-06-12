/**
 * Pure helper functions for the one-shot backfill script.
 *
 * These are intentionally side-effect free so they can be unit-tested
 * without any DB or Kubo connection.
 */

export interface BackfillRow {
  id: string;
  userId: string;
  cid: string;
  isByoUser: boolean;
}

/**
 * D-09 predicate: returns rows that should be deleted from pinned_cids.
 *
 * A row is a deletion candidate if and only if:
 *   1. isByoUser === false  (BYO advisory rows are NEVER touched — D-09 exclusion)
 *   2. cid is absent from the live Kubo pin set  (the row is a phantom)
 *
 * Non-BYO rows whose CID IS in the Kubo set are legitimately pinned — keep them.
 * BYO rows are excluded regardless of Kubo state.
 *
 * NOTE: The caller MUST guard against an empty Kubo set before calling this
 * function. An empty set would cause every non-BYO row to look like a phantom,
 * wiping all quota records. That guard lives in the runnable script (Task 2).
 */
export function selectRowsToDelete(rows: BackfillRow[], kuboPinSet: Set<string>): BackfillRow[] {
  return rows.filter((row) => !row.isByoUser && !kuboPinSet.has(row.cid));
}

/**
 * Parses the NDJSON output of `POST /api/v0/pin/ls?type=recursive` into a
 * Set of CIDs.
 *
 * Kubo streams newline-delimited JSON where each line is an object whose
 * `Keys` property is a map of CID → pin-info (Pitfall 6 from RESEARCH.md).
 * The final stream may span multiple lines and may contain blank lines.
 *
 * Returns an empty Set for blank/whitespace-only input — the caller should
 * treat an empty Set as an abort signal (unreachable/empty Kubo).
 */
export function parseKuboPinLs(text: string): Set<string> {
  const cids = new Set<string>();
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj: unknown = JSON.parse(trimmed);
      if (obj && typeof obj === 'object' && 'Keys' in obj) {
        const keys = (obj as Record<string, unknown>).Keys;
        if (keys && typeof keys === 'object') {
          for (const cid of Object.keys(keys)) {
            cids.add(cid);
          }
        }
      }
    } catch {
      // Non-JSON progress lines — skip silently
    }
  }
  return cids;
}
