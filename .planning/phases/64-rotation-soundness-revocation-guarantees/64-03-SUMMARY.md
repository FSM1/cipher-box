---
phase: 64-rotation-soundness-revocation-guarantees
plan: "03"
subsystem: sdk-core
tags: [rotation, crypto, tdd, fileKey, revocation, aes-256-gcm]

requires:
  - phase: 63-read-chain-navigation-and-rotation-core
    provides: engine.ts scaffold with mintFileKeyOnRotate throwing seam at L200-202
  - phase: 64-02
    provides: mergeChildren three-way merge for SealedChildRef

provides:
  - mintFileKeyOnRotate filled (ROT-03/CRIT-1): mints fileKey' = generateRandomBytes(32) and assigns to node.content.fileKey
  - Folder nodes are a no-op (no content field added, no throw)
  - rotateOne file-node path succeeds; sealNode receives node with new fileKey sealed under readKey'

affects: [64-04, 64-05, 65, 66, 67, 68]

tech-stack:
  added: []
  patterns:
    - "mintFileKeyOnRotate mutates node.content.fileKey in-place (shallow spread in rotateOne makes updatedNode.content === node.content)"
    - "Import generateRandomBytes from @cipherbox/crypto for all key-material generation (never hand-roll)"
    - "Terminal-owner zeroization: do NOT zero node.content.fileKey after assignment — rotateOne consumes via sealNode"

key-files:
  created: []
  modified:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/__tests__/rotation/engine.test.ts

key-decisions:
  - "mintFileKeyOnRotate only assigns fileKey' when node.content is present; no content field added to folder nodes"
  - "No contentRekeyPending field added — NodeContent schema frozen this phase; lazy re-key wiring is Phase 65"
  - "Removed two Phase-63 seam tests that asserted mintFileKeyOnRotate throws — those were placeholder tests for the stub"

patterns-established:
  - "Seam-fill pattern: strip leading underscores from params, replace throw with implementation, update doc-comment"

requirements-completed: [ROT-03]

coverage:
  - id: D1
    description: "mintFileKeyOnRotate mints fileKey' = generateRandomBytes(32) and assigns to node.content.fileKey"
    requirement: ROT-03
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#mintFileKeyOnRotate assigns a fresh 32-byte fileKey to the node content, different from the old key"
        status: pass
    human_judgment: false
  - id: D2
    description: "mintFileKeyOnRotate is a no-op for folder nodes (no content, no throw)"
    requirement: ROT-03
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#is a no-op for nodes without content (folder nodes)"
        status: pass
    human_judgment: false
  - id: D3
    description: "rotateOne file-node integration: sealNode receives the new fileKey after mintFileKeyOnRotate (S7.3 test 2 shape)"
    requirement: ROT-03
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#sealNode receives the new fileKey after mintFileKeyOnRotate"
        status: pass
    human_judgment: false

duration: 2min
completed: 2026-06-29
status: complete
---

# Phase 64 Plan 03: mintFileKeyOnRotate Content-Key Rotation Summary

**mintFileKeyOnRotate seam filled (ROT-03/CRIT-1): rotating a file node now mints fileKey' = generateRandomBytes(32) so a revoked readKey/fileKey holder cannot decrypt the next published version**

## Performance

- **Duration:** 2 min
- **Started:** 2026-06-29T14:11:35Z
- **Completed:** 2026-06-29T14:13:30Z
- **Tasks:** 1 (TDD: RED + GREEN)
- **Files modified:** 2

## Accomplishments

- Filled `mintFileKeyOnRotate` in `packages/sdk-core/src/rotation/engine.ts` — replaces the Phase-63 `throw new Error('not implemented...')` stub at L200-202
- File nodes: mints `fileKey' = generateRandomBytes(32)` from `@cipherbox/crypto` and assigns to `node.content.fileKey` in-place; the subsequent `sealNode` call in `rotateOne` seals the read-body carrying the new fileKey under `readKey'`
- Folder nodes (no content): no-op — no throw, no content field added
- Added 3 TDD assertions covering the fresh-key, no-op, and rotateOne integration behavior
- Removed 2 obsolete Phase-63 placeholder tests that asserted `mintFileKeyOnRotate` throws

## TDD Gate Compliance

- RED commit `a8ee41eae`: 3 new tests fail (seam still throws), 18 existing tests pass
- GREEN commit `9989e2fa5`: all 19 tests pass; seam filled

## Task Commits

1. **RED: content-key rotation tests** - `a8ee41eae` (test)
2. **GREEN: mint fresh fileKey on file rotation** - `9989e2fa5` (feat)

## Files Created/Modified

- `packages/sdk-core/src/rotation/engine.ts` — `mintFileKeyOnRotate` filled; added `generateRandomBytes` import from `@cipherbox/crypto`
- `packages/sdk-core/src/__tests__/rotation/engine.test.ts` — 3 ROT-03 assertions added; 2 Phase-63 stub tests removed

## Decisions Made

- `mintFileKeyOnRotate` only mutates `node.content.fileKey` when `node.content` is present — folder nodes (no content) return early, preserving the conditional D-01 rule
- No `contentRekeyPending` field added to `NodeContent` — the node/v3 schema is frozen this phase per plan prohibition; lazy re-encrypt-on-next-write wiring is Phase 65
- `fileKeyPrime` is NOT zeroed after assignment in `mintFileKeyOnRotate` — `rotateOne` is the terminal consumer via `sealNode` (D-09 / terminal-owner zeroization rule)
- Removed the two Phase-63 seam tests (`mintFileKeyOnRotate throws with "phase 64"` and `rotateOne — file node surfaces Phase-64 throw`) — those were scaffolded for the stub and are superseded by the three new ROT-03 assertions

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. The seam fill is a pure in-memory crypto mutation (Node → Node), bounded inside `rotateOne`'s try/catch block. T-64-03a (CRIT-1) is now mitigated: minting a fresh `fileKey'` breaks the information-disclosure path for a revoked reader who holds the old `fileKey`. T-64-03b (already-distributed content) remains accepted per ADR 0002.

## Next Phase Readiness

- `mintFileKeyOnRotate` is filled and test-proven; `rotateOne` succeeds for both folder and file nodes
- Remaining three seams (`reMintGrantsRootedAt`, `mergeConcurrentChildren`, `verifySubtreeClean`) still throw — handled in plans 64-04, 64-05, 64-06
- Phase 65 owns the write-path lazy re-encrypt that actually re-encrypts content under `fileKey'` on next write

---

*Phase: 64-rotation-soundness-revocation-guarantees*
*Completed: 2026-06-29*
