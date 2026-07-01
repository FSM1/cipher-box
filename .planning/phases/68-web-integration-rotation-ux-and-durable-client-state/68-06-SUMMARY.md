---
phase: 68-web-integration-rotation-ux-and-durable-client-state
plan: 06
subsystem: web
tags: [indexeddb, ipns, rotation, anti-rollback, high-water, sdk]

requires:
  - phase: 68-01
    provides: "createRotationHighWater/enforceResolved SDK state machine over an injected HighWaterStore seam (packages/sdk/src/state/rotation-high-water.ts)"
  - phase: 68-02
    provides: "grant rootGeneration field on share rows/DTOs"
provides:
  - "apps/web/src/services/rotation-state.service.ts — concrete browser IndexedDB HighWaterStore adapter (two stores, D-08 in-memory degradation)"
  - "resolveIpnsRecord (apps/web/src/services/ipns.service.ts) optionally gated through the SDK enforceResolved fail-closed anti-rollback check"
affects: [68-08, 68-09, 68-10]

tech-stack:
  added: []
  patterns:
    - "Raw indexedDB adapter (no idb package), following apps/web/src/lib/device/identity.ts's open/upgrade/validate/degrade shape"
    - "Thin HighWaterStore get/put adapter delegating all monotonic-max/fail-closed logic to the SDK (packages/sdk/src/state/rotation-high-water.ts)"

key-files:
  created:
    - apps/web/src/services/rotation-state.service.ts
  modified:
    - apps/web/src/services/ipns.service.ts

key-decisions:
  - "nodeId for the durable high-water stores is the node's ipnsName — the codebase already uses ipnsName as the SealedChildRef identifier (no separate node UUID at this layer)."
  - "resolveIpnsRecord takes a new OPTIONAL ResolveRotationContext (nodeId, generation, versionFloor, rootGeneration) third-argument-equivalent param. When omitted (the three existing call sites: vault-key-blob resolve and BYO-config resolve in useAuth.ts, folder resync in folder-helpers.ts — none of which are rotation-participating nodes), resolveIpnsRecord behaves exactly as before. When supplied, it seeds the generation floor from rootGeneration on first contact and calls the SDK enforceResolved before returning. This keeps the change additive and backward-compatible with existing callers while wiring the mechanism the plan required."
  - "Once a HighWaterStore degrades to the in-memory session floor (D-08), it latches permanently for the rest of the session rather than retrying IndexedDB per-call — mixing IDB-backed and memory-backed reads for the same logical floor would let the monotonic-max guarantee silently split across two disagreeing backends."

requirements-completed: [ROT-07]

coverage:
  - id: D1
    description: "Two-store (generation-high-water, seq-high-water) raw-indexedDB HighWaterStore adapter satisfying the 68-01 SDK seam, with V5 read-validation and D-08 in-memory degradation + warnedOnce"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/web exec tsc -b (workspace typecheck, SDK dist rebuilt first)"
        status: pass
    human_judgment: false
  - id: D2
    description: "resolveIpnsRecord wired to the SDK enforceResolved fail-closed gate for rotation-participating nodes, seeding the generation floor from a grant's rootGeneration on first contact, never conflated with the read-key unwrap AAD"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/web exec tsc -b (workspace typecheck)"
        status: pass
    human_judgment: true
    rationale: "The actual fail-closed-on-regression and real-reload durability behavior is proven by the 68-10 web-e2e rotation-durability spec, not by this plan (per docs/TESTING.md doctrine, apps/web carries no unit test for this thin adapter/wiring)."

duration: 15min
completed: 2026-07-01
status: complete
---

# Phase 68 Plan 06: IndexedDB Rotation High-Water Adapter + Resolve Enforcement Summary

**Concrete IndexedDB-backed HighWaterStore adapter (two raw-indexedDB stores, D-08 in-memory degradation) behind the 68-01 SDK `createRotationHighWater` seam, plus optional `enforceResolved` anti-rollback gating wired into `resolveIpnsRecord`**

## Performance

- **Duration:** 15 min
- **Started:** 2026-07-01T17:11:00Z
- **Completed:** 2026-07-01T17:15:34Z
- **Tasks:** 2
- **Files modified:** 2 (1 created, 1 modified)

## Accomplishments

- `rotation-state.service.ts` supplies a hand-rolled raw-`indexedDB` adapter (`cipherbox-rotation-state` DB, two object stores `generation-high-water`/`seq-high-water`, both keyed explicitly by `nodeId`) satisfying the SDK's `HighWaterStore` `get`/`put` contract — no `idb` package, no monotonic-max logic duplicated (all delegated to `@cipherbox/sdk`'s `createRotationHighWater`).
- D-08 graceful degradation: each store latches to an in-memory `Map`-backed session floor the first time an IndexedDB operation throws/rejects, and exposes `isRotationStateDegraded()` so a future plan (68-09) can surface a one-time notice.
- `resolveIpnsRecord` in `ipns.service.ts` now accepts an optional `ResolveRotationContext` (`nodeId`, `generation`, `versionFloor`, `rootGeneration`). When supplied, it seeds the durable generation floor from the grant's `rootGeneration` on first contact and calls the SDK's `enforceResolved` before returning the resolved record — throwing `SequenceRegressionError`/`GenerationRegressionError` on any regression, never catching it locally.
- Verified the wiring never references the read-key unwrap AAD path (Pitfall 5) and keeps this a pre-unseal pass/throw gate only.

## Task Commits

Each task was committed atomically:

1. **Task 1: IndexedDB HighWaterStore adapter** - `907d86195` (feat)
2. **Task 2: Wire SDK enforceResolved into resolveIpnsRecord** - `b60511584` (feat)

**Plan metadata:** committed separately by the orchestrator after wave completion (STATE.md/ROADMAP.md are not touched by this parallel executor per its instructions).

## Files Created/Modified

- `apps/web/src/services/rotation-state.service.ts` - New. Raw-indexedDB two-store `HighWaterStore` adapter + D-08 in-memory degradation + shared `createRotationHighWater` instance exporting `seedFromGrant`/`enforceResolved`.
- `apps/web/src/services/ipns.service.ts` - `resolveIpnsRecord` extended with an optional `ResolveRotationContext` parameter; on a rotation-participating resolve, seeds the generation floor from `rootGeneration` and calls `enforceResolved` before returning.

## Decisions Made

- **`nodeId` = `ipnsName`.** The codebase already treats `SealedChildRef.ipnsName` as the effective node identifier throughout `apps/web` (multiple existing `TODO(phase 63)` comments note "SealedChildRef has no `.id`; use `ipnsName` as identifier"). The durable high-water stores are keyed the same way — no new identifier concept introduced.
- **`ResolveRotationContext` is optional and additive.** `resolveIpnsRecord`'s three existing callers (`useAuth.ts` vault-key-blob resolve, `useAuth.ts` BYO-pinning-config resolve, `folder-helpers.ts` conflict resync) resolve non-rotation-participating IPNS names (no `SealedChildRef`, no `generation`/`versionFloor` concept applies to them) and are left untouched, continuing to call `resolveIpnsRecord(ipnsName)` with identical behavior. The rotation context is designed for a caller (a later plan, e.g. 68-08, or a future `packages/sdk/src/client.ts` wiring) that holds a `SealedChildRef` or grant and wants the anti-rollback gate applied. This satisfies the plan's literal wrap-site requirement (`ipns.service.ts:141-149`) without breaking any current caller or requiring changes outside the plan's declared `files_modified`.
- **Degraded stores latch, they don't retry per-call.** Once IndexedDB fails for a store, that store commits to the in-memory session floor for the rest of the session rather than re-attempting IndexedDB on subsequent calls — avoids a split-brain floor where some reads see the IDB-backed value and others see the memory-backed value for the same node.

## Deviations from Plan

None - plan executed exactly as written. The `ResolveRotationContext` parameter shape was Claude's discretion within the plan's explicit instruction to "wrap the return of `resolveIpnsRecord`" and pass `{ nodeId, seq, generation, versionFloor }` to `enforceResolved` — the plan did not specify the exact caller-facing signature, and no caller update was in the declared `files_modified` scope, so the parameter was made optional to preserve the three existing call sites unmodified.

## Issues Encountered

- `apps/web/src/services/__tests__/ipns.service.test.ts` (a pre-existing stale unit test exercising `resolveIpnsRecord`) fails at module-import time with `No "createAxiosInstance" export is defined on the "@cipherbox/api-client" mock` — verified this failure is **pre-existing** (reproduces identically on the base commit before this plan's changes, confirmed via `git stash`/`git stash pop` A/B comparison). Out of scope for this plan (not caused by this plan's edits); left untouched and not counted against verification, consistent with the plan's "no apps/web unit test" doctrine for this work. Logged here for visibility, not fixed (out-of-scope per SCOPE BOUNDARY rule).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The durable `HighWaterStore` adapter and `enforceResolved` wiring are in place for 68-08 (grant fetch / rotation UX wiring) to supply a real `ResolveRotationContext` at an actual `SealedChildRef`/grant-aware call site.
- 68-09 can call `isRotationStateDegraded()` to surface the D-08 one-time degraded-storage notice.
- 68-10's web-e2e rotation-durability spec is the intended real-reload + fail-closed-toast proof point for this plan's logic; no blockers identified.

---
*Phase: 68-web-integration-rotation-ux-and-durable-client-state*
*Completed: 2026-07-01*
