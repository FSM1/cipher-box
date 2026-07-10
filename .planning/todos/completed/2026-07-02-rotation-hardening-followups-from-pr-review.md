---
created: 2026-07-02
title: Rotation hardening follow-ups deferred from Phase 68 PR review
area: sdk/web
files:
  - packages/sdk/src/state/rotation-high-water.ts
  - packages/sdk/src/client.ts
  - packages/sdk-core/src/rotation/engine.ts
  - apps/web/src/services/rotation-driver.service.ts
---

## Retargeted to Phase 70.1 (2026-07-08)

Open items 1 (cross-store bump atomicity) and 5 (reconcile cached generation) are folded into **Phase 70.1** (Rotation Read-Plane Durability), alongside the depth>=2 crash-resume gap and the CodeRabbit floor-write-propagation finding. Close this todo only after verifying items 1 + 5 are actually delivered by 70.1 (no `resolves_phase` marker here on purpose — only 2 of the 6 items remain, so it must not auto-close).

## Phase 70 disposition (2026-07-08)

Partially closed by Phase 70. **Closed:** item 2 (RotateReadResult.readKey terminal-owner zeroization → SC#6, 70-07), item 3 (per-call IndexedDB connections → cached conn, 70-03), item 4 (single-root badge → Set-keyed, 70-03), item 6 (dirty-resume republish result silently dropped → fresh-copy truthy return, 70-06). **Still open (kept in pending):** item 1 (cross-store bump atomicity — explicitly documented out of scope for SC#5 store-layer atomicity at `rotation-high-water.ts:35-46`; needs an atomic multi-store transaction API) and item 5 (reconcile gate feeds cached `nodeGeneration` at `client.ts:1341`, not the freshly-resolved generation). Retarget items 1 + 5 to a future durability phase.

## Problem

Four CodeRabbit findings from the Phase 68 ship review were real but too architectural/risky for a ship-time hot patch:

1. **Cross-store bump atomicity** (`rotation-high-water.ts#enforceResolved`): `bumpFloor(generationStore)` then `bumpFloor(seqStore)` run sequentially; if the second write fails, the two floors diverge until the next successful resolve. Both floors only ever rise, so the divergence is under-protective (not rollback-accepting), but a clean fix needs an atomic multi-store transaction API through the `HighWaterStore` seam — which also has to survive the D-08 in-memory degradation path.
2. **`RotateReadResult.readKey` terminal ownership** (`client.ts#performScopeExitRotation` / `engine.ts#rotateReadFromNode`): the returned `readKey` aliases the engine's `rootResult.childReadKey` frontier buffer. `performScopeExitRotation` already takes a defensive copy into `folderTree`; the ORIGINAL buffer is currently never zeroed. Zeroing it in the client contradicts the phase's documented T-68-12-02 decision and risks the exact callee-zeroes-shared-buffer class that broke 48/89 sdk-e2e once before. Decide the terminal owner deliberately (probably: engine hands over ownership on return → client zeroes after its copy), update the D-09 doc comments on BOTH sides, and prove with sdk-e2e.
3. **Per-call IndexedDB connections** (`rotation-driver.service.ts`): `openJobDB` opens a fresh connection per checkpoint call and never closes it. Cache a shared open-promise (with invalidation on `onversionchange`/close-on-logout).
4. **Single-root badge tracking** (`rotation-driver.service.ts#persistJob`): `activeRootNodeId` is module-global, so concurrent rotations on different roots misclassify each other's root-cut/tail-walk phases and a finishing root resets the badge while another is mid-walk. Durable checkpoints are unaffected (delete is keyed by the finished job's own rootNodeId) — badge-UX only. Track per-root (Set keyed by rootNodeId) and only reset the badge when the set drains.

Two more from CodeRabbit's second-pass PR review (2026-07-02, PR `#587` re-review of the fix commit):

5. **Reconcile gate uses a cached generation, not the freshly-resolved one** (`client.ts#reconcileFolderSequence`): `resolveIpnsRecord` only returns `cid`/`sequenceNumber`/`signatureVerified` — the generation lives inside the sealed node payload, so `enforceResolved` is fed `folderTree.get(ipnsName)?.nodeGeneration ?? 0` (cached local state). Safe direction-wise (floors are monotonic-max, a cached value can only under-bump), but the gate cannot detect a generation regression in the record it just resolved. Either thread the resolved generation through (requires fetching + unsealing inside the reconcile path) or make the cached-fallback contract explicit on `resolveIpnsRecord`/`reconcileFolderSequence`.
6. **Dirty-resume republish result silently dropped** (`engine.ts#rotateReadFromNode` ~890–1199): on the resume path (`rootResult.skipped === true`) with a dirty subtree, the walk can republish the root (bumping the IPNS seq) yet the function still returns `undefined`, so `performScopeExitRotation` never refreshes `folderTree.sequenceNumber` — the exact stale-seq → permanent `ReconcileStaleError` class ROT-07 Gap 2 fixed for the normal path. Surface the republished sequence from the dirty-resume walk and return a truthy result when a real publish occurred.

## Solution

One small hardening plan touching the sites above; items 1–2 and 5–6 need sdk-e2e re-runs, items 3–4 are web-only. Related: the existing rotation-fresh-record-resume todo also touches the driver.

## Resolution

RESOLVED. All six follow-ups are closed:

- Items 2/3/4/6 — closed by Phase 70.
- Item 1 (cross-store bump atomicity) — Phase 70.1 (#598) collapsed the two-store
  seam into a single `CombinedFloorRecord` written via one `store.put`
  (`packages/sdk/src/state/rotation-high-water.ts`, docstring marks "SC#4/D-06
  CLOSED, 70.1-02").
- Item 5 (reconcile cached generation) — Phase 70.1 `reconcileFolderSequence`
  now re-resolves + `unsealNode(folderReadKey)` and feeds the freshly-resolved
  `generation` into `enforceResolved` rather than the cached `folderTree` value
  (`packages/sdk/src/client.ts`, SC#5/D-09).

Retired 2026-07-11 via pending-todo triage.
