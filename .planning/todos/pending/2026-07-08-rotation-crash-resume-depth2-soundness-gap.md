---
created: 2026-07-08
title: Rotation crash-resume is unsound for depth>=2 trees — dirty-frontier consumption is depth-1-only and reuses a stale child key
area: sdk-core
severity: high
source: PR #596 review (greptile P1 + CodeRabbit critical/major)
files:
  - packages/sdk-core/src/rotation/engine.ts
  - tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts
---

## Problem

Phase 70 (70-05/70-06) made `verifySubtreeClean`/`collectDirtyFrontier` recurse the full subtree and return `DirtyFrontierItem`s at any depth, but the **consumption** paths only handle depth-1. The Phase 70 sdk-e2e gate passed **vacuously**: Test 4 (fresh-record resume) uses a childless root by deliberate design and Test 2 crashes only at the final persist, so no test ever presents a real dirty edge at depth>=2. Three PR-review findings (all REAL, confirmed by trace) live in code the suite never reaches.

### T2/T8 — dirty-resume consumption is depth-1-only (`engine.ts:1401-1442`)

The `rootResult.skipped` dirty-resume loop looks each frontier item up ONLY in `rootNode.children` by `ipnsName` (`:1403-1405`) and hard-codes `parentIpnsName: rootNodeIpnsName` (`:1424`); it never consults `frontierItem.parentIpnsName`. A depth-2+ dirty node → `.find()` undefined → `:1410` decrements the ROOT's `pendingChildCount` and drops the item. No `parentTracking` is seeded for the intermediate parent, its stale mirror is never republished, and the spurious decrements drive root to zero → **job completes "successfully" while a stale mid-tree mirror remains**. `pendingChildCount` is seeded to `frontier.length` (`:1397`), mixing in depth-2+ items.

### T2/T8 normal-branch ordering (depth>=3) (`engine.ts:1523-1524`, `:1559`, `:1568`)

The normal branch threads `parentIpnsName` correctly but appends dirty items after root's children. A deep dirty node D sits ahead of its below-depth-1 parent P2 in the queue; when D is dequeued first, `parentTracking.get(item.parentIpnsName)` (`:1568`) is undefined → re-seal/decrement skipped, D added to `completedNodeIds`. When P2 later re-enqueues D, `rotateOne` returns `skipped:true` and the `if (!result.skipped)` guard (`:1559`) skips the decrement again → **P2's pendingChildCount for D never decrements, P2 never republishes**.

### T1 — stale dirty-key reuse (`engine.ts:661-666`)

For a dirty edge (`childPub.generation > childRef.generation`), `resolveChildKeyAndEnvelope` derives `childReadKey` from the parent mirror's `childRef.readKeySealed` — but that mirror lags, so the key is the child's PRE-rotation key. It is stored as `nodeReadKey` and later fed to `rotateOne` (`:1548`) which `unsealNode(child's CURRENT body, staleKey)` → AEAD throws → **crash-resume throws instead of converging**. This is entangled with the known hard limitation (RESEARCH.md Pitfall 4 / `verifySubtreeClean` docstring `:613-619`): the child's post-rotation key is cryptographically unrecoverable from the durable floor. A correct fix treats an already-rotated dirty node as node-converged and repairs only the parent mirror.

## Why deferred (not fixed in Phase 70 ship)

All three are LARGE/structural and require new depth>=2/>=3 mid-tree crash-resume e2e coverage that does not exist. T1 additionally needs a design decision about repairing a parent mirror when the child's post-rotation key is unrecoverable. This exceeds a ship-time hot patch and is a follow-on to Phase 70's SC#2/SC#3 (which are proven only for depth-1 / childless-root as shipped). PR #596 discloses this limitation.

## Solution sketch

- Make the dirty-resume branch depth-aware: reconstruct parent chains from the frontier, seed `parentTracking` for each intermediate parent (needs their IPNS key, generation, sealed-children snapshot, per-parent pending accounting), stop attributing everything to the root.
- Normal branch: order parents-before-children (or defer dirty enqueue until the parent's tracking exists); close the `:1559`/`:1568` skip-path decrement gap.
- T1: treat an already-rotated dirty node as converged; repair only the parent mirror; decide the key source for that re-seal.
- Add a depth-2 (and depth-3) mid-walk-crash e2e to `rotation-crash-safety.test.ts` that navigates + unseals the deep subtree after resume.
