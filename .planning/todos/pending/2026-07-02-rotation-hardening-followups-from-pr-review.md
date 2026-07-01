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

## Problem

Four CodeRabbit findings from the Phase 68 ship review were real but too architectural/risky for a ship-time hot patch:

1. **Cross-store bump atomicity** (`rotation-high-water.ts#enforceResolved`): `bumpFloor(generationStore)` then `bumpFloor(seqStore)` run sequentially; if the second write fails, the two floors diverge until the next successful resolve. Both floors only ever rise, so the divergence is under-protective (not rollback-accepting), but a clean fix needs an atomic multi-store transaction API through the `HighWaterStore` seam — which also has to survive the D-08 in-memory degradation path.
2. **`RotateReadResult.readKey` terminal ownership** (`client.ts#performScopeExitRotation` / `engine.ts#rotateReadFromNode`): the returned `readKey` aliases the engine's `rootResult.childReadKey` frontier buffer. `performScopeExitRotation` already takes a defensive copy into `folderTree`; the ORIGINAL buffer is currently never zeroed. Zeroing it in the client contradicts the phase's documented T-68-12-02 decision and risks the exact callee-zeroes-shared-buffer class that broke 48/89 sdk-e2e once before. Decide the terminal owner deliberately (probably: engine hands over ownership on return → client zeroes after its copy), update the D-09 doc comments on BOTH sides, and prove with sdk-e2e.
3. **Per-call IndexedDB connections** (`rotation-driver.service.ts`): `openJobDB` opens a fresh connection per checkpoint call and never closes it. Cache a shared open-promise (with invalidation on `onversionchange`/close-on-logout).
4. **Single-root badge tracking** (`rotation-driver.service.ts#persistJob`): `activeRootNodeId` is module-global, so concurrent rotations on different roots misclassify each other's root-cut/tail-walk phases and a finishing root resets the badge while another is mid-walk. Durable checkpoints are unaffected (delete is keyed by the finished job's own rootNodeId) — badge-UX only. Track per-root (Set keyed by rootNodeId) and only reset the badge when the set drains.

## Solution

One small hardening plan touching the four sites above; items 1–2 need sdk-e2e re-runs, items 3–4 are web-only. Related: the existing rotation-fresh-record-resume todo also touches the driver.
