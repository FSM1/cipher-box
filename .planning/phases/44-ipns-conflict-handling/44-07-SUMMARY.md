---
phase: 44-ipns-conflict-handling
plan: "07"
subsystem: sdk-core/file
tags: [bugfix, data-integrity, tdd, prunedCids, ipns-conflict, cr-02, wr-08]
dependency_graph:
  requires: [44-03]
  provides: [prunedCids-reference-filter]
  affects: [useFileOperations.ts unpin loop, useFileVersions.ts unpin loop]
tech_stack:
  added: []
  patterns: [referenced-Set filter on accumulated prunedCids, TDD red-green cycle]
key_files:
  created: []
  modified:
    - packages/sdk-core/src/file/index.ts
    - packages/sdk-core/src/__tests__/file.test.ts
decisions:
  - "Build referenced Set from mergedMetadata.cid + mergedMetadata.versions[].cid after conflict merge, not from winner/loser intermediates"
  - "De-dupe accumulated prunedCids (new Set) before filtering to prevent phantom duplicate unpin entries"
  - "Reorder: build mergedMetadata BEFORE accumulating prunedCids so referenced set is available for filter"
metrics:
  duration: "~12 minutes"
  completed: "2026-06-13T00:21:45Z"
  tasks_completed: 1
  tasks_total: 1
  files_modified: 2
---

# Phase 44 Plan 07: CR-02 prunedCids Reference Filter + WR-08 File Test

Fixes CR-02: in `updateFileMetadata`, accumulated `prunedCids` are now filtered against the
set of CIDs actually referenced by the published `mergedMetadata` before returning.

## What Was Built

### CR-02 Fix — `packages/sdk-core/src/file/index.ts`

After building `mergedMetadata` in the 409 conflict branch, the code now:

1. Builds a `Set<string>` of referenced CIDs from `mergedMetadata.cid` and every
   `mergedMetadata.versions[].cid` (the published record's complete reference set).
2. De-dupes the accumulated `prunedCids` via `new Set([...prunedCids, ...extraPruned])`.
3. Filters: keeps only CIDs NOT in the referenced set.

This prevents a CID that was pruned in the pre-conflict positional slice but resurrected into
`mergedMetadata.versions[]` by the remote merge from being returned to callers for unpinning.
Without this fix, `useFileOperations.ts:507-510` would unconditionally unpin a CID that the
currently-published IPNS record still references, permanently destroying version content.

### WR-08 Test — `packages/sdk-core/src/__tests__/file.test.ts`

Added one new test: `WR-08: prunedCids does not contain CIDs referenced by the published mergedMetadata (CR-02 filter)`

The test reproduces the exact CR-02 bug scenario:

- `currentMetadata.versions` is deliberately unsorted (`[v-old(ts=100), v-NEW(ts=9000)]`)
- `createVersion=true` with `maxVersionsPerFile=2` causes positional `slice(2)` to prune
  `v-NEW` (high timestamp but at position 1 in the tail)
- Remote retains `v-NEW` in its `versions[]`, causing `mergeVersions` to resurrect it
- `v-NEW` ends up in both the initial `prunedCids` AND the final `mergedMetadata.versions`

Three assertions:

- **(a)** Retry `encryptFileMetadata` payload (`mock.calls[1][0]`) contains `v-NEW` in `versions[]`
  (confirms loser/resurrected data is present in the published record)
- **(b)** `result.prunedCids ∩ publishedRefs = ∅` (CR-02 core invariant — zero overlap)
- **(c)** `result.prunedCids` contains `v-old` (genuinely overflowed, not referenced — confirms
  the filter is not over-broad)

TDD gate: RED commit `bc017a9bb` → GREEN commit `e161f4f5d`.

## Commits

| Hash | Type | Description |
|------|------|-------------|
| `bc017a9bb` | test | Add failing WR-08 assertion for CR-02 prunedCids reference filter |
| `e161f4f5d` | fix | Filter prunedCids against mergedMetadata references in file 409 path |

## Deviations from Plan

None — plan executed exactly as written. The implementation matches the exact expression
prescribed in 44-VERIFICATION.md Gap 2 and the PLAN.md action block.

## Acceptance Criteria Verification

- `grep -c "referenced" packages/sdk-core/src/file/index.ts` = 3 (comment + Set construction + filter predicate)
- Filter uses `mergedMetadata.cid` and `mergedMetadata.versions` (the published record, not winner/loser intermediates)
- `new Set([...prunedCids, ...extraPruned])` de-dupes before filter
- `file.test.ts` captures `encryptFileMetadata.mock.calls[1][0]` and asserts: loser/resurrected cid in versions[], overlap = empty, non-referenced overflow still pruned
- `pnpm --filter @cipherbox/sdk-core test src/__tests__/file.test.ts` passes (14/14 tests)

## TDD Gate Compliance

RED gate: `test(44-07)` commit `bc017a9bb` — 1 failing test (WR-08)
GREEN gate: `fix(44-07)` commit `e161f4f5d` — all 14 tests passing

Both gates present in git log in correct order.

## Known Stubs

None.

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes.
The fix is a pure in-memory filter within the existing `updateFileMetadata` function.

## Self-Check: PASSED

- `e161f4f5d` present in git log: confirmed
- `bc017a9bb` present in git log: confirmed
- `packages/sdk-core/src/file/index.ts` modified: confirmed
- `packages/sdk-core/src/__tests__/file.test.ts` modified: confirmed
- All 14 file suite tests passing: confirmed
