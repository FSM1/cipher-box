---
phase: 65-sdk-write-chain-bin-re-link-and-invite-claim
plan: "05"
subsystem: sdk-core/rotation
tags: [rotation, write-plane, tdd, security]
dependency_graph:
  requires: ["65-01"]
  provides: ["nodeWriteKey-threading-in-rotateOne"]
  affects: ["packages/sdk-core/src/rotation/engine.ts"]
tech_stack:
  added: []
  patterns:
    - "fail-closed guard: writeSealed present without valid writeKey throws"
    - "writeKeyForReseal = node.writeBody ? nodeWriteKey : empty (never zeros)"
    - "nodeKeySource return extended with optional writeKey for BFS threading"
key_files:
  created:
    - packages/sdk-core/src/__tests__/rotation/write-body-reseal.test.ts
  modified:
    - packages/sdk-core/src/rotation/engine.ts
decisions:
  - "writeKeyForReseal uses new Uint8Array(0) when node has no writeBody — sealNode ignores writeKey when writeBody absent, so empty is semantically correct and avoids re-introducing any all-zeros 32-byte placeholder"
  - "nodeKeySource return type extended with writeKey?: Uint8Array — root writeKey sourced from nodeKeySource(rootIpnsName) rather than adding a rootWriteKey param, keeping RotationParams stable"
  - "Fail-closed guard placed AFTER unseal, BEFORE mint — mirrors IPNS-key guard pattern at same location"
metrics:
  duration: "7 minutes"
  completed: "2026-06-29"
  tasks_completed: 2
  files_modified: 1
  files_created: 1
status: complete
---

# Phase 65 Plan 05: Wire writeKey into Read-Rotation Engine Summary

Threads the real `writeKey` through the read-rotation engine and removes the all-zeros `PLACEHOLDER_WRITE_KEY` from all three seal sites in `rotateOne`, folding FLAG-63-U1 (rotateone-placeholder-writekey-phase65 / D-05).

## What Was Built

Read-rotation of write-capable nodes now preserves the write plane. Before this plan, any node with a write-body sealed (`writeSealed` present in its published envelope) would have its write plane silently corrupted during rotation — `rotateOne` called `unsealNode` without a writeKey (write-body dropped) and re-sealed via `sealNode` with `PLACEHOLDER_WRITE_KEY = new Uint8Array(32)` (all-zeros) at three sites.

### Changes to `packages/sdk-core/src/rotation/engine.ts`

- Added `nodeWriteKey?: Uint8Array` to `RotateOneParams`.
- Extended `nodeKeySource` return type with `writeKey?: Uint8Array`.
- Changed `unsealNode(published, parentReadKey)` to `unsealNode(published, parentReadKey, nodeWriteKey)` — recovers write-body when writeKey is supplied.
- Added fail-closed guard AFTER unseal: if `published.writeSealed` is present and `nodeWriteKey` is absent or all-zeros, throws with a descriptive error (mirrors the existing IPNS-key guard at the same location).
- Computed `writeKeyForReseal = node.writeBody ? nodeWriteKey! : new Uint8Array(0)` and used it at all three `sealNode` sites: the main reseal, the no-base CAS-409 branch, and the `mergeConcurrentChildren` call.
- Deleted `const PLACEHOLDER_WRITE_KEY = new Uint8Array(32)` (0 references remain).
- In `rotateReadFromNode`: added `nodeWriteKey` field to the BFS queue type; threaded `nodeKeySource?.(name)?.writeKey` through at root, normal-child, dirty-resume-child, grandchild enqueue sites and at the BFS `rotateOne` call.
- Retained the existing IPNS private-key fail-closed guard unchanged.

### New test: `packages/sdk-core/src/__tests__/rotation/write-body-reseal.test.ts`

Seven tests covering:

- Tests 1-4 (Suite 1): `unsealNode` receives `nodeWriteKey` as 3rd arg; `sealNode` receives the real non-zero writeKey not an all-zeros placeholder; the node handed to `sealNode` has its `writeBody.ipnsPrivateKey` preserved; generation is bumped by 1.
- Tests 5-6 (Suite 2): Fail-closed guards — `writeSealed` present without `nodeWriteKey` throws; all-zeros `nodeWriteKey` throws.
- Test 7 (Suite 3): `rotateReadFromNode` BFS threads `nodeKeySource.writeKey` through to each `sealNode` call.

## Deviations from Plan

None — plan executed exactly as written.

## Threat Surface Scan

No new network endpoints, auth paths, or schema changes introduced. The changes are internal to `rotateOne` / `rotateReadFromNode` (pure in-memory crypto wiring). T-65-17 and T-65-18 (write-body tampering and silent write-plane drop) are now mitigated by the fail-closed guard and the write-body reseal.

## TDD Gate Compliance

- RED commit `4fc453910`: `test(65-05): add failing write-body-reseal tests` — 6 of 7 tests failed.
- GREEN commit `e26a2d039`: `feat(65-05): thread real writeKey through rotateOne, remove PLACEHOLDER_WRITE_KEY` — all 7 tests pass; 36 existing engine tests pass.

## Self-Check: PASSED

- FOUND: `packages/sdk-core/src/__tests__/rotation/write-body-reseal.test.ts`
- FOUND: `packages/sdk-core/src/rotation/engine.ts`
- FOUND: `.planning/phases/65-sdk-write-chain-bin-re-link-and-invite-claim/65-05-SUMMARY.md`
- Commit `4fc453910` exists: RED test commit
- Commit `e26a2d039` exists: GREEN implementation commit
