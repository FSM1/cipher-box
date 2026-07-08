---
created: 2026-06-29
title: Fresh-record crash-resume not implemented (verifySubtreeClean gated on non-empty completedNodeIds); SC#4 no-double-bump contradicts the design's double-rotation model
area: sdk-core
resolves_phase: 68
files:
  - packages/sdk-core/src/rotation/engine.ts
  - tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts
  - .planning/ROADMAP.md
---

## Problem

Surfaced during Phase 64 (ROT-06) execution and verification (plan 64-07 + e2e 64-08, deviations #1/#2). User decision 2026-06-29: ship Phase 64 as-is, defer this.

Phase 64 ROADMAP success criterion #4 reads: *"A crash mid-walk is recovered by re-running `rotateReadFromNode`; `verifySubtreeClean` rebuilds the frontier from published IPNS records, re-run converges **without double-bumping** any node's generation, and the revoked recipient is cut from the root after the root step."* Two problems:

### 1. SC#4 "without double-bumping" contradicts the design

Design `.planning/design/2026-06-26-sharing-read-keychaining-design.md` §4.5 is explicit that the crash-recovery path **is** a double-rotation:

> "if the job record is lost between 'published N at readKey'' and 'rewrote parent link,' the new key is gone and the parent link cannot be re-sealed to match. Resolution: **a fresh full `rotateOne(N)` is the recovery path** — generate `readKey''`/`gN''`, seal the parent link with `readKey''`, publish both. **An extra rotation only strengthens revocation** and costs one republish. **Double-rotation safety is what lets the published IPNS state be the sole source of truth.**"

So a second bump is the *intended, safe* recovery mechanism. The 64-07 convergence guard (engine.ts L878, frontier-children only) tried to enforce SC#4's stricter "no double-bump," which over-constrained against the design and produced the corner below. **SC#4's wording should be corrected** to the design's model: recovery converges *idempotently or via safe double-rotation*, not "without double-bumping."

### 2. Fresh-record resume (D-03) is not actually implemented

D-03 specified: resume by calling `rotateReadFromNode` again with a **FRESH** `RotationJobRecord` (empty `completedNodeIds`); `verifySubtreeClean` rebuilds the frontier from published IPNS truth (D-10). In the shipped code:

- `verifySubtreeClean(rootNodeIpnsName, rootReadKey, ctx)` is only called when `completedNodeIds` is **non-empty** (engine.ts ~L643/L760: "A fresh run (completedNodeIds empty) does NOT call verifySubtreeClean"). A genuinely fresh resume skips it and re-enters `rotateOne(root)`.
- `rotateOne(root)` immediately `unsealNode(publishedRoot, rootReadKey)`. After a crash where the root was already rotated, the published root is under `readKeyPrime_root` (NEW) while a fresh resume only holds the OLD `rootReadKey` → **AEAD failure**.
- The convergence-skip guard (L878) covers only **frontier children** (via the parent mirror `SealedChildRef[N].generation`). The **root has no parent mirror**, so it is never skipped; its done-check via its own plaintext envelope generation is not wired into the fresh-resume path.

Consequence: the e2e (`rotation-crash-safety.test.ts`, test 2) could only make resume work by **(a)** crashing at the final `status='complete'` persist (N=4, after all rotation + D-09 republishes finish — not a true mid-walk crash), and **(b)** seeding the resume job's `completedNodeIds` with the crash-time set and passing the captured `readKeyPrime_root` as `rootReadKey`. That is the **durable-job-record + persisted-keys model = Phase 68**, not the fresh-record-from-published-truth model D-03 described.

## Root cause / scope boundary

To re-read or re-rotate an already-rotated node on resume you need its CURRENT (new) key. For non-root nodes the parent holds the child's `readKeySealed` (under the parent's key), so given the root's current key the subtree is recoverable. For the **root** there is no parent — the resuming host must independently hold the root's current key/generation. That is exactly the **M1 durable client floor** (`{nodeId → highestGeneration}` + the minted keys) deferred to **Phase 68**. Phase 64's job record is advisory/in-memory by decision, so full fresh-resume self-heal of an already-rotated root is genuinely Phase-68-blocked.

## Fix (Phase 68)

1. Correct ROADMAP SC#4 wording to the design's double-rotation recovery model (idempotent-or-safe-double-rotation, not "no double-bump").
2. Wire the durable client floor (Phase 68 ROT-07) so a resuming host holds the highest minted generation + key per node; then implement the true fresh-record resume: empty `completedNodeIds` → `verifySubtreeClean` rebuilds the frontier from the parent-mirror-vs-child-envelope generation comparison (no key needed for the done-CHECK) → safe double-rotation recovery for in-flight edges per design §4.5, including a root done-check via the root's own published envelope generation.
3. Replace the seeded-`completedNodeIds` e2e resume with a genuine fresh-record resume once the durable floor exists.

## Why deferred

User-decided 2026-06-29 (Phase 64 close): ship the phase with the achievable resume behavior proven (post-completion crash recovery + concurrent-add merge + multi-level happy-path), defer true fresh-record resume to the Phase-68 durable floor. Related: [[rotation-concurrent-add-merge-downgrades-rotated-child-readkey]].
