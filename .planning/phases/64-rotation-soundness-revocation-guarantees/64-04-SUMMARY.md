---
phase: 64
plan: "04"
subsystem: sdk-core/rotation
tags:
  - rotation
  - tdd
  - security
  - ipns
  - fail-closed
dependency_graph:
  requires:
    - 64-01 (D-06 nodeId/nodeGeneration stability)
    - 64-02 (D-07 unseal-child AAD invariant)
    - 64-03 (D-08 fileKey mint seam)
  provides:
    - D-01 fail-closed IPNS publish guard (no PLACEHOLDER_WRITE_KEY)
    - D-02 parent-link re-seal in BFS caller (out-of-band)
    - D-09 batched parent publish after all children rotate
  affects:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/__tests__/rotation/engine.test.ts
tech_stack:
  added:
    - updateFolderMetadataAndPublish from folder/registration (for D-09)
    - ParentTrackingState in-memory Map per BFS traversal
  patterns:
    - TDD RED/GREEN per task
    - BFS parent tracking map for batched out-of-band operations
    - Fail-closed IPNS signing guard
key_files:
  modified:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/__tests__/rotation/engine.test.ts
decisions:
  - "D-02 re-seal is out-of-band in BFS caller (rotateReadFromNode), not inside rotateOne — preserves rotateOne's single-responsibility contract"
  - "parentTracking Map keyed by IPNS name enables O(1) lookup when decrementing pending child count"
  - "RotateOneDone.newSequenceNumber added to thread CAS sequence guard to D-09 parent re-publish"
  - "childPubId/childPubKind added to BFS queue items for AAD binding in sealChildReadKey D-02 call"
  - "ParentTrackingState.pendingChildCount decremented on rotateOne success; skipped nodes do not trigger re-seal"
metrics:
  duration: "~60 minutes (continuation session)"
  completed: "2026-06-29"
  tasks_completed: 4
  tasks_total: 4
  files_modified: 2
status: complete
---

# Phase 64 Plan 04: D-01 Fail-Closed Guard, D-02 Parent Re-Seal, D-09 Batched Parent Publish Summary

One-liner: Deleted PLACEHOLDER_WRITE_KEY fallback, wired per-node IPNS keys via nodeKeySource callback, and fixed the Phase-63 CRITICAL re-seal bug by re-sealing child readKey' under parent's new readKey' out-of-band in the BFS caller with a single batched parent re-publish.

## Tasks Completed

| Task | Commit | Description |
|------|--------|-------------|
| 1 RED | 45366dd | test(64-04): RED tests for D-01 fail-closed publish and nodeKeySource |
| 1 GREEN | 376aa1b | feat(64-04): D-01 fail-closed publish guard and nodeKeySource BFS threading |
| 2 RED | fa42b25 | test(64-04): RED tests for D-02 parent re-seal and D-09 batched parent publish |
| 2 GREEN | 0b34043 | feat(64-04): D-02 parent-link re-seal and D-09 batched parent publish |

## What Was Built

### Task 1 — D-01 Fail-Closed Guard + nodeKeySource Threading

Deleted the `PLACEHOLDER_WRITE_KEY` (all-zeros 32-byte fallback) from `rotateOne`. Added a fail-closed guard that throws if `nodeIpnsPrivateKey` is absent before minting `readKeyPrime`. Added `nodeKeySource?: (ipnsName: string) => { privateKey: Uint8Array; publicKey: Uint8Array } | undefined` to `RotationParams` and threaded per-node IPNS keys through the BFS queue items at enqueue time for both root-children and grandchildren.

Guard placement: after the second idempotency check (skipped nodes never need a key), before minting `readKeyPrime` (keeps the catch-block zeroization simple).

### Task 2 — D-02 Parent Re-Seal + D-09 Batched Parent Publish

Fixed the Phase-63 CRITICAL bug where `sealChildReadKey` inside `rotateOne` sealed the child's new `readKey'` under the child's own old `parentReadKey` (legacy misnomer). The parent's `SealedChildRef[N].readKeySealed` must be sealed under the PARENT's new `readKey'` for `unsealChildReadKey` to authenticate.

Fix is out-of-band in `rotateReadFromNode` (the BFS caller):

1. `RotateOneDone` gained `newSequenceNumber: bigint` — captured from `publishWithCas` return for CAS guard threading.
2. `ParentTrackingState` type and `parentTracking: Map<string, ParentTrackingState>` — holds parent's new readKey', IPNS keys, nodeId, generation, last CAS sequence, a mutable SealedChildRef copy, and a `pendingChildCount`.
3. After root's `rotateOne`: populate `parentTracking` entry for root.
4. After each child's `rotateOne` succeeds: call `sealChildReadKey(childReadKey', parentNewReadKey', childPubId, childPubKind, newGeneration)`, update the mutable SealedChildRef copy, decrement `pendingChildCount`, call `updateFolderMetadataAndPublish` exactly once when count reaches 0.
5. BFS queue items gained `childPubId: string` and `childPubKind: 'folder' | 'file'` (from `resolveAndFetch` at enqueue time) for AAD binding in the D-02 sealChildReadKey call.

The D-09 batched re-publish uses the parent's `newSequenceNumber` (from the parent's own `rotateOne`) as the CAS `sequenceNumber` guard, advancing the IPNS monotonic counter by 1 without bumping `generation` again.

## TDD Gate Compliance

Both tasks followed the RED/GREEN TDD cycle:

- Task 1 RED: `test(64-04)` commit (45366dd) — 4 failing tests added
- Task 1 GREEN: `feat(64-04)` commit (376aa1b) — implementation passes all tests
- Task 2 RED: `test(64-04)` commit (fa42b25) — 3 failing tests added
- Task 2 GREEN: `feat(64-04)` commit (0b34043) — all 26 tests pass

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] TypeScript tuple destructuring error in Task 2 RED test**

- **Found during:** Task 2 GREEN typecheck phase
- **Issue:** `sealChildReadKey.mock.calls.some(([...]: [Uint8Array, Uint8Array, string, string, number]) => ...)` was not assignable to `(value: any[]) => unknown` because TypeScript couldn't narrow `any[]` to a 5-tuple
- **Fix:** Changed to `callArgs.some((callArgs: unknown[]) => { const parentKey = callArgs[1] as Uint8Array; ... })` — same pattern used for the D-01 RED test fix in the previous session
- **Files modified:** packages/sdk-core/src/__tests__/rotation/engine.test.ts
- **Commit:** Included in 0b34043 (GREEN commit)

## Known Stubs

None added in this plan. The Phase-64 D-09 stub comment on the BFS loop (referencing "per-node parent-link publish, not batched in Phase 63") was replaced with the real implementation.

## Threat Flags

None. No new network endpoints, auth paths, or schema changes. The `parentTracking` Map is in-memory only and cleared when each parent's re-publish completes.

## Verification

```
pnpm --filter @cipherbox/sdk-core test --run src/__tests__/rotation/engine.test.ts
Test Files  1 passed (1)
Tests       26 passed (26)
```

TypeScript: zero new errors in engine.ts / engine.test.ts. Pre-existing errors in `cas.test.ts` and `share/grant.test.ts` are known and out-of-scope.

## Self-Check: PASSED

- [x] engine.ts exists and includes ParentTrackingState, parentTracking Map, D-02 sealChildReadKey out-of-band call, D-09 updateFolderMetadataAndPublish batched publish
- [x] All 4 commits exist: 45366dd, 376aa1b, fa42b25, 0b34043
- [x] 26/26 tests pass
- [x] No new TypeScript errors in engine files
