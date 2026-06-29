---
phase: 64-rotation-soundness-revocation-guarantees
plan: "06"
subsystem: sdk-core/rotation
tags: [tdd, rotation, cas, concurrent-merge, ROT-05]
requires: [64-02, 64-05]
provides: [ROT-05-concurrent-add-merge]
affects: [sdk-core/cas, sdk-core/rotation/engine, sdk-core/folder/merge]
tech-stack:
  added: []
  patterns: [three-way-merge, async-merge-callback, tdd-red-green]
key-files:
  created: []
  modified:
    - packages/sdk-core/src/cas.ts
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/__tests__/rotation/engine.test.ts
decisions:
  - "merge callback union type (sync | Promise) keeps cas.ts backward-compatible with registration.ts sync callers"
  - "local children taken from closure (node.children) instead of unsealing localPub — avoids 4th unsealNode call and readKeyPrime dependency during merge"
  - "vi.resetAllMocks() instead of vi.clearAllMocks() in beforeEach — drains mockResolvedValueOnce queues preventing RED-test contamination of D-02/D-09 tests"
metrics:
  duration: "~13 minutes"
  completed: "2026-06-29"
  tasks: 2
  files: 3
status: complete
---

# Phase 64 Plan 06: CAS-409 Concurrent-Add Merge Summary

Fills the `mergeConcurrentChildren` seam (ROT-05/HIGH-4) in `rotation/engine.ts`: on a CAS-409 during rotation, re-decodes base and remote under the OLD readKey, three-way merges children via `mergeChildren`, and re-seals under readKeyPrime.

## What Was Built

### Task 1 — RED (commit `54e337832`)

Added 4 failing tests to `engine.test.ts` in a new `describe('CAS-409 concurrent-add merge — ROT-05/HIGH-4 (Plan 64-06)')` block:

- **Test 1:** concurrent child add survives — merged node includes the remote-only child
- **Test 2:** merge re-decodes the REMOTE node — 3 `unsealNode` calls prove remote was decoded
- **Test 3:** merge re-seals under readKey-prime — both `sealNode` calls share the same (non-old) key
- **Test 4:** happy path — no 409 never invokes the merge callback (1 unseal, 1 seal)

Helper `setupCas409Mock(basePub, localPub, remotePub)` simulates a CAS-409 by invoking `params.merge` directly via `await Promise.resolve(...)`.

Tests 1-3 failed with `"not implemented — phase 64 (ROT-05/HIGH-4 concurrent-add merge): CAS-409 on rotation publish"`. Test 4 passed.

### Task 2 — GREEN (commit `d57989ae7`)

**`packages/sdk-core/src/cas.ts`**
- Changed `merge` callback type to `sync | Promise` union: `| Promise<{ merged: TData; prunedCids?: string[] }>`
- Wrapped call site with `await Promise.resolve(params.merge(...))` for backward-compat with sync callers (registration.ts unchanged)

**`packages/sdk-core/src/rotation/engine.ts`**
- Added `import { mergeChildren } from '../folder/merge'`
- Implemented `mergeConcurrentChildren(basePub, remotePub, oldReadKey, localChildren, newReadKey, localNode, generationPrime, writeKey): Promise<PublishedNode>`:
  1. `unsealNode(basePub, oldReadKey)` → base children
  2. `unsealNode(remotePub, oldReadKey)` → remote children
  3. `mergeChildren(base, local, remote)` → merged children (union, remote wins, prune intentional deletes)
  4. `sealNode({ ...localNode, generation: generationPrime, children: merged }, newReadKey, writeKey)` → new `PublishedNode`
- Replaced the Phase-63 `throw new Error('not implemented...')` stub in `rotateOne`'s merge callback with an async closure that calls `mergeConcurrentChildren`

**`packages/sdk-core/src/__tests__/rotation/engine.test.ts`**
- Removed the `'mergeConcurrentChildren throws with "phase 64"'` stub test (seam now filled)
- Removed `mergeConcurrentChildren` from the named import (no longer directly tested)
- Changed `vi.clearAllMocks()` → `vi.resetAllMocks()` in both 64-06 and D-02 `beforeEach` blocks (see Rule 1 deviation below)

**Result:** 29/29 tests pass. Zero new TypeScript errors in engine.ts, cas.ts, or engine.test.ts.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed pre-existing D-02/D-09 test failures caused by `mockResolvedValueOnce` queue contamination**

- **Found during:** RED phase — D-02 and D-09 tests failed with wrong values (`hasD02Call === false`, `publishCalls.length === 1`) even before any GREEN changes.
- **Root cause:** `vi.clearAllMocks()` clears call history and mock.results but does NOT drain the `mockResolvedValueOnce` queue. The 64-06 RED tests set `unsealNode.mockResolvedValueOnce(localNode).mockResolvedValueOnce(baseNode).mockResolvedValueOnce(remoteNode)` and then FAIL (merge throws). The unconsumed `Once` values persisted across test boundaries, so D-02/D-09 tests received wrong node objects from `unsealNode` (wrong generation → `gen === 3` instead of `gen === 1` → `hasD02Call === false`).
- **Fix:** Changed `vi.clearAllMocks()` to `vi.resetAllMocks()` in both affected `beforeEach` blocks. `resetAllMocks` drains the Once queues AND clears call state.
- **Files modified:** `packages/sdk-core/src/__tests__/rotation/engine.test.ts`
- **Commits:** `d57989ae7`

**2. [Rule 1 - Bug] Removed `mergeConcurrentChildren` unused import after deleting its direct-call stub test**

- Removing the `'mergeConcurrentChildren throws with "phase 64"'` test left the import unused, causing TS6133 error.
- **Fix:** Removed `mergeConcurrentChildren` from the named import in `engine.test.ts`. The function is now tested indirectly through `rotateOne` (the 64-06 tests call `rotateOne` which calls `mergeConcurrentChildren` internally via the merge callback).
- **Commits:** `d57989ae7`

## TDD Gate Compliance

- RED gate: commit `54e337832` (`test(64-06): add failing CAS-409 concurrent-add tests`)
- GREEN gate: commit `d57989ae7` (`feat(64-06): merge concurrent child adds on rotation CAS-409`)
- REFACTOR gate: not required (no cleanup needed)

## Self-Check: PASSED

- `packages/sdk-core/src/cas.ts` — modified in commit `d57989ae7` ✓
- `packages/sdk-core/src/rotation/engine.ts` — modified in commit `d57989ae7` ✓
- `packages/sdk-core/src/__tests__/rotation/engine.test.ts` — modified in commits `54e337832`, `d57989ae7` ✓
- 29/29 engine tests pass ✓
- Zero new type errors (pre-existing cas.test.ts/grant.test.ts errors unchanged) ✓
