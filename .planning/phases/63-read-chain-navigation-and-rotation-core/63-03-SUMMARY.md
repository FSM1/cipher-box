---
phase: 63-read-chain-navigation-and-rotation-core
plan: 03
subsystem: sdk-core/rotation
tags: [rotation-engine, read-revocation, cas-publish, tdd, phase-64-seams]
status: complete

dependencies:
  requires:
    - 62: node/v3 codec (sealNode/unsealNode/sealChildReadKey from @cipherbox/core)
    - 63-01: read-chain navigation walk
    - 63-02: grant issuance and invite re-wrap
  provides:
    - rotateReadFromNode: resumable BFS rotation walk (ROT-01)
    - rotateOne: per-node CAS-commit rotation step
    - 4 named Phase-64 seams (mintFileKeyOnRotate, reMintGrantsRootedAt, mergeConcurrentChildren, verifySubtreeClean)
    - RotationJobRecord type with advisory persistCallback
  affects:
    - packages/sdk-core/src/rotation/engine.ts (new)
    - packages/sdk-core/src/__tests__/rotation/engine.test.ts (new)

tech-stack:
  added: []
  patterns:
    - TDD RED/GREEN (vi.hoisted mock pattern from cas.test.ts)
    - Named Phase-64 seam discipline (mirrors Phase-62 D-01)
    - publishWithCas-based per-node CAS commit
    - Advisory job record with optional persistCallback (D-10)
    - String-literal unions for RotationStatus (no TypeScript enums)

key-files:
  created:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/__tests__/rotation/engine.test.ts
  modified: []

decisions:
  - rotateOne uses parentReadKey to unseal child (not the child's own key); for root nodes parentReadKey is the root's own readKey
  - write-body re-seal skipped in Phase 63 (read-chain only per RESEARCH.md resolved Q1); placeholder writeKey used safely because updatedNode.writeBody is always absent
  - nodeId is optional in rotateOne params: fast idempotency when provided, derived from unsealed node when absent (needed for frontier BFS where SealedChildRef has no childId)
  - D-09 batched-parent-publish deferred: rotateOne publishes child only (1 publishWithCas call); parent-link update returned for caller to handle
  - CAS-409 in merge callback throws Phase-64 (not silent last-write-wins) to surface ROT-05 gap

metrics:
  duration: 16m
  completed: 2026-06-29
  tasks_completed: 2
  files_created: 2
  tests_added: 18
---

# Phase 63 Plan 03: Rotation Engine Summary

One-liner: `rotateReadFromNode` + `rotateOne` in named `src/rotation/engine.ts` file — root-first BFS walk with per-node CAS commit and four conditionally-invoked Phase-64 named seams.

## What Was Built

### Task 1: rotateOne skeleton + 4 named Phase-64 seams (TDD)

RED commit `01908b07d`: 18 failing tests covering the rotateOne happy path, seam throws, file-node trigger, zeroization invariant, and rotateReadFromNode BFS ordering/completion/persistCallback.

GREEN commit `9640ddabd`: `packages/sdk-core/src/rotation/engine.ts` implementing:

- `rotateOne` — 9-step §4.5 walk: resolve → unseal under parentReadKey → mint readKey' (generation+1) → conditionally invoke mintFileKeyOnRotate seam (file nodes only) → reseal under readKey' → sealChildReadKey for parent ref → publishWithCas(child, sequenceNumber: resolved.sequenceNumber) → mark done → conditionally invoke reMintGrantsRootedAt seam (inner grants only)
- `mintFileKeyOnRotate` — throws `not implemented — phase 64 (ROT-03/CRIT-1 content-key rotation)`
- `reMintGrantsRootedAt` — throws `not implemented — phase 64 (ROT-04/HIGH-3 inner-grant re-mint)`
- `mergeConcurrentChildren` — throws `not implemented — phase 64 (ROT-05/HIGH-4 concurrent-add merge)`
- `verifySubtreeClean` — throws `not implemented — phase 64 (ROT-06 crash-resume + verifySubtreeClean)`
- `RotationJobRecord` type with string-literal `RotationStatus` union
- `RotationParams` type

### Task 2: rotateReadFromNode resumable frontier walk (TDD)

Implemented in the same GREEN commit. `rotateReadFromNode` does:

1. Sets status 'in-progress'
2. Rotates root FIRST (§4.2 — the actual cut for the revoked reader)
3. Calls persistCallback after root commit (high-value checkpoint)
4. BFS frontier: for each child in root.children, enqueues `{ ipnsName, parentReadKey: rootReadKey' }`
5. While queue non-empty: rotateOne(child) → persistCallback → enqueue grandchildren
6. Sets status 'complete'

Fresh runs skip `verifySubtreeClean` (Phase-64 seam — D-01/D-10).

## Acceptance Criteria Check

- `packages/sdk-core/src/rotation/engine.ts` exists (NOT index.ts) — coverage 83.14% (SC#5 verified)
- `export async function rotateOne` count: 1
- `export async function rotateReadFromNode` count: 1
- 4 seams present (mintFileKeyOnRotate, reMintGrantsRootedAt, mergeConcurrentChildren, verifySubtreeClean): each tested individually asserting `/phase 64/` message
- Happy-path folder rotateOne test passes WITHOUT any seam throw
- No `enum ` in engine.ts
- No FUSE/Tauri/web imports
- All 18 tests pass

## Deviations from Plan

None — plan executed exactly as written.

Minor implementation decisions within Claude's Discretion scope:

- `nodeId` is optional in `rotateOne` params: fast idempotency when provided, derived from `node.id` post-unseal when absent. Needed because `SealedChildRef` has no `childId` field, so `rotateReadFromNode` cannot know child nodeIds before unsealing them.
- Placeholder writeKey (`new Uint8Array(32)`) used in `sealNode` call; safe because `updatedNode.writeBody` is always absent in Phase 63 (we unsealed with readKey only, no writeKey), so `sealNode` never accesses the writeKey argument.
- merge callback in `publishWithCas` throws Phase-64 error on 409 (not silent last-write-wins), to explicitly surface the ROT-05 gap.

## Known Stubs

None — the four Phase-64 seams are explicitly named and throw (not silent stubs that could mask gaps).

## Threat Flags

No new security-relevant surface introduced beyond what is in the plan's threat model (T-63-09, T-63-10, T-63-11, T-63-12 are all addressed by the implementation).

## Self-Check: PASSED

- engine.ts: FOUND
- engine.test.ts: FOUND
- Commit 9640ddabd: FOUND
- Commit 01908b07d: FOUND
