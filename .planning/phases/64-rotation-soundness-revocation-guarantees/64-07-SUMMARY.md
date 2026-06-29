---
phase: 64-rotation-soundness-revocation-guarantees
plan: "07"
subsystem: sdk-core/rotation
tags: [rotation, tdd, crash-resume, convergence, zeroization]
dependency_graph:
  requires: [64-06]
  provides: [ROT-06, D-07-fix, convergence-guard, terminal-persist]
  affects:
    - packages/sdk-core/src/rotation/engine.ts
tech_stack:
  added: []
  patterns:
    - "BFS dirty-edge frontier from published IPNS records (D-10 source-of-truth)"
    - "Crash-resume convergence guard (no-double-bump via enqueuedGeneration)"
    - "D-07 completedNodeIds ordering: add AFTER reMintGrantsRootedAt succeeds"
    - "Terminal-owner zeroization: engine-derived BFS readKeys zeroed after use"
key_files:
  created: []
  modified:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/__tests__/rotation/engine.test.ts
decisions:
  - "verifySubtreeClean accepts (rootIpnsName, rootReadKey, ctx) — needs IPNS name + read key to resolve and unseal root's sealed body to get the SealedChildRef list"
  - "Convergence guard uses enqueuedGeneration field (parent mirror at enqueue time) as baseline; resolveAndFetch called once per BFS item before rotateOne"
  - "Dirty-resume path uses rootReadKey as parentNewReadKey proxy — root was rotated in prior run but rootReadKey still unseals (confirmed by verifySubtreeClean)"
  - "Terminal persistCallback call added after jobRecord.status = 'complete' — Pitfall 5 prevention"
  - "queue-derived item.nodeReadKey zeroed after grandchild enqueue loop — engine is terminal owner of BFS-derived readKeys"
metrics:
  duration: "~40 minutes (including context restoration from compaction)"
  completed: "2026-06-29"
  tasks_completed: 4
  files_changed: 2
status: complete
---

# Phase 64 Plan 07: verifySubtreeClean, Resume Guard, and D-07 Ordering Summary

One-liner: ROT-06 crash-resume convergence via IPNS-sourced dirty-edge frontier, no-double-bump guard, D-07 completedNodeIds ordering, terminal persist, and BFS readKey zeroization.

## What Was Built

### Task 1: verifySubtreeClean + Resume Guard + Convergence Guard

**verifySubtreeClean (ROT-06):**
Implements a BFS read-only pass over the subtree rooted at `rootIpnsName`. Resolves each node from IPNS (source of truth per D-10), unseals the root to get the `SealedChildRef` list, and for each child resolves the child's published generation. If `childPub.generation > childRef.generation` (parent mirror is stale), the child is added to the dirty frontier. Returns `{ isDirty: boolean; frontier: Array<{ ipnsName, nodeId }> }`.

**Resume guard rewrite (Pitfall 5 fix):**
The old guard at the `rootResult.skipped` check immediately set `jobRecord.status = 'complete'` without calling `verifySubtreeClean`. This meant a crash where the root committed but children did not would never be detected or completed. The new guard calls `verifySubtreeClean` first:
- Clean (`isDirty: false`): mark complete, persist, return.
- Dirty: re-fetch root from IPNS, seed BFS queue from dirty frontier nodes, fall through to BFS loop.

**Convergence guard (no-double-bump):**
Added `enqueuedGeneration: number` field to BFS queue items (set to `childRef.generation` at enqueue time — parent mirror/baseline). Before each `rotateOne(item)` in the BFS loop, calls `resolveAndFetch` to get the child's current published generation. If `currentPub.generation > item.enqueuedGeneration`, the child already rotated in a prior run — skip `rotateOne`. Still handles D-09: decrements `parentState.pendingChildCount` and triggers `updateFolderMetadataAndPublish` when count reaches zero.

### Task 2: D-07 Ordering, Terminal Persist, Queue-Key Zeroization

**D-07 completedNodeIds ordering fix:**
Moved `jobRecord.completedNodeIds.add(nodeId)` to AFTER `reMintGrantsRootedAt` succeeds in `rotateOne`. Previously the add ran before the re-mint; a failed re-mint left `nodeId` in `completedNodeIds`, causing the node to be silently skipped on resume. With the fix, a failed re-mint propagates out through the existing `catch` block, `completedNodeIds` is never written, and the node is retried on resume.

**Terminal persistCallback:**
Added `if (jobRecord.persistCallback) await jobRecord.persistCallback(jobRecord)` after `jobRecord.status = 'complete'` at the end of `rotateReadFromNode`. The advisory job record is now durably checkpointed at walk completion, enabling the host to safely discard the in-memory record.

**Queue-derived child readKey zeroization (D-09 terminal-owner):**
Added `item.nodeReadKey.fill(0)` after the grandchild enqueue loop in the BFS. The engine derives child readKeys via `unsealChildReadKey` — it is the terminal owner of these buffers and must zero them once their consumers (grandchildren) have been enqueued. The caller-supplied `rootReadKey` is never touched (caller is terminal owner per D-09).

## TDD Gate Compliance

All 4 commits followed strict RED → GREEN ordering:

1. `test(64-07): add failing tests for verifySubtreeClean resume and convergence guard` — e68786633
2. `feat(64-07): fill verifySubtreeClean and rewrite resume guard with convergence guard` — a274a8ee4
3. `test(64-07): add failing tests for D-07 ordering terminal persist and queue-key zeroization` — 5bf2a1093
4. `feat(64-07): fix D-07 ordering terminal persist and queue-key zeroization` — c08d03d6e

RED states: Tests 1, 2, 3, 5 (Task 1) and Tests 1, 2, 3 (Task 2) all failed correctly before implementation. Test 4 (clean-resume) passed in RED as expected (regression gate — the old code happened to handle that path correctly).

Final: 36 tests pass.

## Commits

| Hash | Type | Description |
|------|------|-------------|
| e68786633 | test | Task 1 RED: verifySubtreeClean resume convergence guard tests |
| a274a8ee4 | feat | Task 1 GREEN: verifySubtreeClean, resume guard, convergence guard |
| 5bf2a1093 | test | Task 2 RED: D-07 ordering, terminal persist, zeroization tests |
| c08d03d6e | feat | Task 2 GREEN: D-07 fix, terminal persist, queue-key zeroization |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] verifySubtreeClean signature changed from 2-arg to 3-arg**
- **Found during:** Task 1 RED
- **Issue:** The original stub had `(rootNodeId, ctx)` but a BFS verification needs the IPNS name (not node ID) to resolve the record, plus the readKey to unseal the root node and access the SealedChildRef children list.
- **Fix:** Changed signature to `(rootIpnsName: string, rootReadKey: Uint8Array, ctx: SdkContext)`. Removed the old 2-arg throw test and replaced with 5 new 3-arg tests.
- **Files modified:** engine.ts, engine.test.ts
- **Commit:** e68786633, a274a8ee4

**2. [Rule 3 - Blocking] GrantRemintCallbacks import removed then re-added across tasks**
- **Found during:** Task 1 RED commit
- **Issue:** ESLint `no-unused-vars` blocked commit — `GrantRemintCallbacks` was imported for Task 2 tests that hadn't been written yet.
- **Fix:** Removed import for Task 1 RED commit; re-added for Task 2 RED commit.
- **Files modified:** engine.test.ts

**3. [Rule 2 - Auto] `parentTracking` and `resolveAndFetch` moved before resume guard**
- **Found during:** Task 1 GREEN
- **Issue:** The resume guard needed `parentTracking` (Map) and `resolveAndFetch` (helper) to seed the dirty BFS queue, but these were defined AFTER the old guard's early-return. Required restructuring to define them before the `if (rootResult.skipped)` check.
- **Fix:** Moved both definitions above the resume guard; restructured as `if/else` instead of early-return pattern. No behavioral change to existing normal path.
- **Files modified:** engine.ts

## Pre-existing Typecheck Errors (Out of Scope)

`npx tsc --noEmit -p packages/sdk-core/tsconfig.json` reports errors in `cas.test.ts` and `share/grant.test.ts` — confirmed pre-existing (present in the commit before any changes in this plan). Not introduced by this plan.

## Known Stubs

None. All seams filled by this plan are implemented with full logic. The dirty-resume path uses `rootReadKey` as a proxy for `parentNewReadKey` in the D-09 parent tracking setup — this is a known simplification acknowledged in comments (the root was rotated in a prior run; the original readKey still unseals as confirmed by verifySubtreeClean's successful call).

## Threat Flags

None. No new network endpoints, auth paths, file access patterns, or schema changes introduced.

## Self-Check: PASSED

- engine.ts modified: FOUND
- engine.test.ts modified: FOUND
- Commit e68786633: FOUND
- Commit a274a8ee4: FOUND
- Commit 5bf2a1093: FOUND
- Commit c08d03d6e: FOUND
- 36/36 tests passing: CONFIRMED
