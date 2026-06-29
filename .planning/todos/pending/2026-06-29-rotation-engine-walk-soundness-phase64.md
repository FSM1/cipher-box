---
created: 2026-06-29
title: Rotation engine walk + job-record soundness — CodeRabbit findings deferred to Phase 64
area: sdk-core
resolves_phase: 64
files:
  - packages/sdk-core/src/rotation/engine.ts
  - packages/sdk-core/src/__tests__/rotation/engine.test.ts
---

## Problem

The Phase-63 CodeRabbit review surfaced several rotation-engine correctness/soundness findings. These are deferred to **Phase 64 (Rotation Soundness — Revocation Guarantees)** because they live in the multi-node BFS walk + crash-resume machinery that Phase 64 owns and will rework when it fills the four named seams (`mintFileKeyOnRotate`, `reMintGrantsRootedAt`, `mergeConcurrentChildren`, `verifySubtreeClean`). The Phase-63 happy path (single root-step rotation; first-level child hits the Phase-64 stub) is verified working and does NOT reach these paths.

Findings (CodeRabbit severities in brackets):

- **[CRITICAL] BFS drops the rotated child link** (`engine.ts` ~L335-341, ~L495-554): `rotateOne` computes `newReadKeySealed` via `sealChildReadKey`, but the BFS caller drops the returned value and never writes it back to the parent's `SealedChildRef.readKeySealed`/`.generation`. A multi-level subtree rotation therefore would not propagate the new child key to parents. Fix the BFS loop to persist `newReadKeySealed` (and the generation mirror) onto the parent ref and republish. (Related test gap: [MAJOR] `engine.test.ts` ~L247-268 only asserts `sealChildReadKey` was *called*, not that its output updates the parent ref and is republished — strengthen it.)
  - **[CRITICAL refinement — greptile P1, `engine.ts:97/337`]** `newReadKeySealed` is currently sealed under the **wrong key**. After the 63-07 e2e fix, `RotateOneParams.parentReadKey` carries the node's OWN pre-rotation readKey (used to unseal the node's read-body), so step-7 computes `sealChildReadKey(readKeyPrime, nodeOwnOldReadKey, …)`. But for the parent's `SealedChildRef[N].readKeySealed` to unseal, the seal key must be the **parent's NEW readKey'** (`parentNewReadKeyPrime`), not the child's own old key. So simply writing `newReadKeySealed` back to the parent (the bullet above) is NOT sufficient — Phase 64 must either pass the parent's new readKey as a separate param or re-seal out-of-band using the child's returned `childReadKey`, or every non-root rotated node will hit an AEAD auth failure on later `unsealChildReadKey`. (The misleading `parentReadKey` doc-comment was corrected in the Phase-63 ship; the field name remains a legacy misnomer pending this rework.)
- **[CRITICAL] Placeholder write-key publish fallback** (`engine.ts` ~L346-349): the publish path falls back to `PLACEHOLDER_WRITE_KEY` when `ipnsPrivateKey` is undefined. Never publish an IPNS record signed/sealed with a placeholder — require a real key or fail closed. (The write-body placeholder itself is tracked separately in `2026-06-29-rotateone-placeholder-writekey-phase65.md` for Phase 65; this finding is about the *publish* path guarding against undefined inputs.)
- **[MAJOR] Job-record completion marked too early** (`engine.ts` ~L376-383): `jobRecord.completedNodeIds.add(nodeId)` happens before downstream steps (e.g. `reMintGrantsRootedAt`); on retry/resume a failed re-mint is skipped because the node is already "complete". Move the add to after the node is fully processed.
- **[MAJOR] Resume fast-path marks complete incorrectly** (`engine.ts` ~L288-290): when `rootNodeId` is already in `completedNodeIds`, `rotateReadFromNode` can mark the resumed walk complete and skip processing `jobRecord.frontier`, bypassing the `verifySubtreeClean` resume seam. Fix the resume guard.
- **[MAJOR] Terminal job status not persisted** (`engine.ts` ~L557-558): the normal completion path updates `jobRecord.status` only in memory; persist the terminal state via the host-injected persistence callback on successful finish (ties into ROT-07 durable resume, Phase 68, but the in-engine ordering is Phase 64).
- **[MAJOR] BFS queue leaks derived child read keys** (`engine.ts` ~L495-554): child read keys stored in queue entries are not zeroed after use; zero them once a queue item's children are derived/enqueued (terminal-owner — these are engine-derived, safe to zero).
- **[MAJOR] Missing resume + failure-path tests** (`engine.test.ts` ~L292-312, ~L315-352): add a resumed-rotation test (`completedNodeIds` non-empty) and a failure-path zeroization test (force publish/seal rejection after `readKeyPrime` is minted; assert the minted key is zeroed and caller-supplied `parentReadKey` is NOT).

## Solution

Address as part of Phase 64's rotation-soundness implementation, when the four seams are filled and the resumable walk + `verifySubtreeClean` convergence are built. Re-run the full CodeRabbit review on the Phase-64 branch to confirm closure.

## References

- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` §4.2 (ordering), §4.5 (rotateOne 9-step / per-node commit / crash recovery / verifySubtreeClean), §4.4 (HIGH-3 re-mint)
- `.planning/phases/63-read-chain-navigation-and-rotation-core/63-CONTEXT.md` D-01 (the 63→64 seam line), D-10 (job record)
- ROADMAP Phase 64 (Rotation Soundness — Revocation Guarantees); requirements ROT-03..ROT-06
