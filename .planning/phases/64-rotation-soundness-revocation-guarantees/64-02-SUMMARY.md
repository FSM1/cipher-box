---
phase: 64-rotation-soundness-revocation-guarantees
plan: "02"
subsystem: sdk-core/folder
tags: [tdd, merge, sealed-child-ref, rot-05, high-4]
dependency_graph:
  requires: []
  provides: [mergeChildren-SealedChildRef]
  affects: [registration.ts updateFolderMetadataAndPublish merge callback, rotation engine CAS-409 re-merge (Plan 64-06)]
tech_stack:
  added: []
  patterns: [three-way merge, union-by-key, intentional-delete pruning]
key_files:
  created: []
  modified:
    - packages/sdk-core/src/folder/merge.ts
    - packages/sdk-core/src/__tests__/folder-merge.test.ts
decisions:
  - "Union semantics: local inserted first, remote overwrites on conflict (remote wins); one-sided delete kept by union"
  - "Intentional delete: pruned only when absent from BOTH local AND remote (base presence is the anchor)"
  - "Pure structural merge: no crypto ops, no mutation of readKeySealed or any sealed bytes"
metrics:
  duration: 3min
  completed: 2026-06-29
status: complete
---

# Phase 64 Plan 02: mergeChildren Three-Way Merge Summary

**One-liner:** Filled Phase-64 `mergeChildren` stub with union-by-ipnsName three-way merge (remote wins on conflict, intentional deletes honored) and revived the folder-merge test suite to SealedChildRef.

## What Was Built

Filled `mergeChildren(base, local, remote): never` in `packages/sdk-core/src/folder/merge.ts` with the three-way merge semantics required by ROT-05/HIGH-4. The stub previously threw `not implemented — phase 64`; it now returns `SealedChildRef[]`.

### Algorithm

1. Build a `Map<string, SealedChildRef>` keyed by `ipnsName`.
2. Insert all `local` entries first.
3. Insert all `remote` entries (remote overwrites on conflict — concurrent add / CAS-409 favors remote, design §3.7).
4. For each `ipnsName` in `base` that is absent from BOTH `local` AND `remote`, delete it from the map (intentional both-sides delete is honored).
5. Return `Array.from(map.values())`.

### Test Coverage (folder-merge.test.ts)

The quarantined `describe.skip('mergeChildren — TODO(phase 64)')` block referencing the retired `FolderChild` types was replaced with a live `describe('mergeChildren')` block using `SealedChildRef`:

| Test | Scenario | Assertion |
|------|----------|-----------|
| T1 | Concurrent add: child only in remote | B is in result |
| T2 | Remote wins on conflict: same ipnsName | `result[0]` is the remote object |
| T3 | Both-sides delete: C absent from local AND remote | C not in result |
| T4 | One-sided delete: C in local, absent from remote | C in result (union wins) |
| T5 | Return type: does not throw | Array.isArray(result) true |
| + | Immutability: base/local/remote lengths unchanged after call | Lengths equal |

ConflictError and is409 test suites preserved unchanged (12 tests).

## TDD Gate Compliance

- RED commit `ecf64c5e2`: `test(64-02): add failing three-way merge tests for SealedChildRef` — 6 mergeChildren tests failing, 12 ConflictError/is409 passing.
- GREEN commit `1aad8adfd`: `feat(64-02): implement mergeChildren three-way merge for SealedChildRef` — all 18 tests passing.
- No REFACTOR commit needed: implementation is minimal and clean.

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None — `mergeChildren` is fully implemented and returns correct results.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes. The merge function is pure in-memory logic with no I/O.

## Self-Check

- `packages/sdk-core/src/folder/merge.ts` — FOUND (modified)
- `packages/sdk-core/src/__tests__/folder-merge.test.ts` — FOUND (modified)
- Commit `ecf64c5e2` (RED) — FOUND in git log
- Commit `1aad8adfd` (GREEN) — FOUND in git log

## Self-Check: PASSED
