---
phase: 68-web-integration-rotation-ux-and-durable-client-state
plan: 08
subsystem: web
tags: [rotation, navigator-locks, indexeddb, zustand, sdk, owner-reconcile]

requires:
  - phase: 68-05
    provides: "RotationClientCallbacks/LocalGrantRecord injection seam types + performScopeExitRotation composing maybeRotateOnScopeExit/rotateReadFromNode, wired into CipherBoxClient's four mutation methods"
  - phase: 68-04
    provides: "useRotationStore (beginRootCut/beginTailWalk/markResuming/reset) presentation-only badge state machine"
  - phase: 68-06
    provides: "IndexedDB HighWaterStore adapter pattern (rotation-state.service.ts) this plan's job-checkpoint store mirrors"
  - phase: 68-07
    provides: "owner-reconcile.service.ts eager login sweep (triggerOwnerReconcileOnLogin) this plan extends with a single-root variant"
  - phase: 68-02
    provides: "useShareStore sentShares carrying ipnsName/rootNodeId/rootGeneration — the grant-getter data source"
provides:
  - "apps/web/src/lib/multi-tab-lock.ts — withTailWalkLeader (navigator.locks leader election + idempotent fallback, D-09)"
  - "apps/web/src/services/rotation-driver.service.ts — buildRotationClientCallbacks() concrete RotationClientCallbacks, metadata-only durable job checkpoint, badge-lifecycle wiring, resumeInterruptedRotation()"
  - "rotationCallbacks injected at CipherBoxClient construction in useAuth.ts; resumeInterruptedRotation() called once per app-open"
  - "D-11 opportunistic post-mutation owner-reconcile trigger (runOwnerReconcileForFolder) fired on every folder:updated event, alongside the 68-07 eager login sweep"
  - "RotationClientCallbacks/LocalGrantRecord now re-exported from @cipherbox/sdk's public index (were previously types.ts-only, unreachable by any consumer)"
affects: [68-09, 68-10]

tech-stack:
  added: []
  patterns:
    - "navigator.locks leader election with a direct-call fallback (first Web Locks API use in this codebase) — the fallback is a correctness-preserving no-op, not a degraded mode, because the tail walk is idempotent (D-09)"
    - "Durable job checkpoint is a SANITIZED projection of RotationJobRecord — rootNodeId/status/completedNodeIds/frontier ipnsNames only, never frontier[].parentReadKey or ipnsPrivateKey bytes (Pitfall 4)"
    - "Badge-lifecycle inference from persistJob call cadence: first non-terminal call per rootNodeId -> beginRootCut, subsequent calls for the same root -> beginTailWalk, terminal status -> reset (see rotation-driver.service.ts's @security doc comment for why persistJob rather than progress carries this signal)"

key-files:
  created:
    - apps/web/src/lib/multi-tab-lock.ts
    - apps/web/src/services/rotation-driver.service.ts
  modified:
    - apps/web/src/hooks/useAuth.ts
    - apps/web/src/services/owner-reconcile.service.ts
    - packages/sdk/src/index.ts

key-decisions:
  - "Badge-phase signal source: the SDK chokepoint (performScopeExitRotation) awaits the FULL rotation (root cut + entire tail walk) before the triggering mutation resolves, and its only per-phase hook is RotationJobRecord.persistCallback (this plan's persistJob) — persistJob is called once right after the root commits, then once per subsequent tail-walk node commit, then once more with status 'complete'. There is no earlier 'root cut is about to start' hook in the current SDK. This plan therefore treats the FIRST non-terminal persistJob call for a given rootNodeId as the root-cut signal and every SUBSEQUENT call as tail-walk progress, documented in rotation-driver.service.ts's module doc. The 'progress' callback (which the SDK only ever calls once, with 'rotated', at full completion) is wired defensively with forward-compatible 'root-cut'/'tail-walk' cases in case a future SDK change emits them directly."
  - "resumeInterruptedRotation() surfaces the durable checkpoint's 'resuming' badge state but does NOT replay a partial walk: performScopeExitRotation builds a fresh, empty RotationJobRecord on every mutation call, so there is no SDK entrypoint today that accepts a pre-seeded completedNodeIds set. This is a pre-existing, already-flagged gap (see sdk-core's verifySubtreeClean doc comment and the 'rotation-fresh-record-resume-and-sc4-double-bump' todo), not something this thin apps/web adapter can close without an SDK-side change. The durable checkpoint is left in place (not deleted) on resume so a future SDK resume entrypoint can consume it; published IPNS records remain the source of truth in the meantime (D-10), so this gap never leaves a subtree insecure -- it only leaves the local badge in 'resuming' until the next genuine mutation on that subtree re-triggers a fresh rotation."
  - "The opportunistic post-mutation owner-reconcile trigger subscribes to the SDK's existing folder:updated event (fired by renameItem/deleteItem/deleteToBin/moveItem after their metadata publish) and treats event.ipnsName as the affected root — this matches the SAME ipnsName performScopeExitRotation uses as rootNodeIpnsName for those same mutations, so 'the affected root' is correctly identified without new SDK event plumbing."
  - "Job-checkpoint storage is a dedicated IndexedDB database ('cipherbox-rotation-jobs') owned entirely by rotation-driver.service.ts, separate from rotation-state.service.ts's high-water DB ('cipherbox-rotation-state') -- this plan's files_modified scope does not include rotation-state.service.ts, and a job checkpoint (rootNodeId/status/completedNodeIds/frontier metadata) is a structurally different concern from the two high-water floor stores."

requirements-completed: [ROT-07]

coverage:
  - id: D1
    description: "withTailWalkLeader elects one tab via navigator.locks to drive the tail walk, falling back to a direct call (both tabs idempotent) when Web Locks is unavailable"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/web exec tsc --noEmit (grep-gated: navigator.locks + withTailWalkLeader present, no apps/web test file added)"
        status: pass
    human_judgment: true
    rationale: "Per docs/TESTING.md this is thin apps/web glue with zero unit-test requirement -- the real multi-tab leader-election and idempotent-fallback behavior is proven by the 68-10 web-e2e rotation-ux spec, not written in this plan."
  - id: D2
    description: "buildRotationClientCallbacks() supplies persistJob (metadata-only durable checkpoint, never key material), progress (badge mapping), and grant getters sourced from useShareStore; resumeInterruptedRotation() surfaces the 'resuming' badge on load"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/web exec tsc --noEmit (grep-gated: zero .fill(0) occurrences, beginRootCut/beginTailWalk/markResuming >= 2, resumeInterruptedRotation present)"
        status: pass
    human_judgment: true
    rationale: "Thin, untested adapter per docs/TESTING.md -- badge lifecycle and resume-after-reload behavior is proven by the 68-10 web-e2e rotation-ux spec, not by this plan's own tests."
  - id: D3
    description: "rotationCallbacks injected at CipherBoxClient construction, resumeInterruptedRotation called once per app-open, and runOwnerReconcileForFolder fires opportunistically after folder:updated events alongside the 68-07 login sweep"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/web exec tsc --noEmit (grep-gated: buildRotationClientCallbacks/resumeInterruptedRotation/runOwnerReconcile all present in useAuth.ts)"
        status: pass
    human_judgment: true
    rationale: "Thin wiring-only hook per plan instruction ('no rotation/reconcile logic inline') -- exercised end-to-end only by the 68-10 web-e2e spec, not a dedicated unit test in this plan."

duration: 30min
completed: 2026-07-01
status: complete
---

# Phase 68 Plan 08: Rotation Progress UX + Multi-Tab Coordination + Durable Client State Summary

**Concrete web driver (navigator.locks leader election, metadata-only IndexedDB job checkpoint, and rotation.store badge wiring) behind the 68-05 SDK rotation injection seam, plus a D-11 opportunistic post-mutation owner-reconcile trigger**

## Performance

- **Duration:** ~30 min
- **Completed:** 2026-07-01
- **Tasks:** 3
- **Files modified:** 5 (2 created, 3 modified — 2 of the 3 modified files beyond the plan's declared 3, see Deviations)

## Accomplishments

- `apps/web/src/lib/multi-tab-lock.ts` — first use of the Web Locks API in this codebase: `withTailWalkLeader()` elects one tab to drive the rotation tail walk via `navigator.locks.request()`, falling back to a direct call when Web Locks is unavailable (safe, per D-09's idempotent-walk + CAS-409-re-merge design)
- `apps/web/src/services/rotation-driver.service.ts` — `buildRotationClientCallbacks()` supplies the concrete `RotationClientCallbacks`: a metadata-only durable job checkpoint (`persistJob`, never key bytes), badge-lifecycle mapping onto `rotation.store` (`beginRootCut`/`beginTailWalk`/`reset`), and grant getters sourced from `useShareStore`'s sent-grant state; `resumeInterruptedRotation()` surfaces the `'resuming'` badge on app load when a durable checkpoint is found
- `rotationCallbacks` wired into `CipherBoxClient` construction in `useAuth.ts`; `resumeInterruptedRotation()` called once per app-open
- D-11 opportunistic post-mutation owner-reconcile: a new `runOwnerReconcileForFolder()` in `owner-reconcile.service.ts` (single-root variant of the existing eager login sweep) fires on every `folder:updated` event from `useAuth.ts`
- `RotationClientCallbacks`/`LocalGrantRecord` re-exported from `@cipherbox/sdk`'s public index — these types existed since 68-05 but were never reachable by any consumer

## Task Commits

Each task was committed atomically:

1. **Task 1: navigator.locks leader election + idempotent fallback** - `e4bddcb52` (feat)
2. **Task 2: rotation-driver.service — concrete callbacks + resume-on-load** - `b559df02a` (feat)
3. **Task 3: inject rotation callbacks + post-mutation reconcile trigger** - `d3eaa8a19` (feat)

**Plan metadata:** committed separately by the orchestrator after wave completion (STATE.md/ROADMAP.md are not touched by this parallel executor per its instructions).

## Files Created/Modified

- `apps/web/src/lib/multi-tab-lock.ts` - New. `withTailWalkLeader(fn)` — navigator.locks exclusive-lock wrapper + direct-call fallback.
- `apps/web/src/services/rotation-driver.service.ts` - New. `buildRotationClientCallbacks()`, `resumeInterruptedRotation()`, a dedicated `cipherbox-rotation-jobs` IndexedDB store for the sanitized job checkpoint.
- `apps/web/src/hooks/useAuth.ts` - `rotationCallbacks: buildRotationClientCallbacks()` added to the SDK client config; `resumeInterruptedRotation()` fire-and-forget call added alongside the 68-07 eager owner-reconcile sweep; `sdkClient.on(...)` subscription added for the `folder:updated` opportunistic reconcile trigger.
- `apps/web/src/services/owner-reconcile.service.ts` - New `runOwnerReconcileForFolder(rootIpnsName)` export — single-root variant of `triggerOwnerReconcileOnLogin`, reusing its existing `decodeSentGrants`/`makeReconcileJob`/`buildReconcileCtx`/`webOwnerReconcileTransport` helpers.
- `packages/sdk/src/index.ts` - Added `RotationClientCallbacks`/`LocalGrantRecord` to the existing `export type { ... } from './types'` block.

## Decisions Made

See `key-decisions` in frontmatter for the full rationale on each of the following:

- **Badge-phase signal source is `persistJob` call cadence, not `progress`.** The SDK's `performScopeExitRotation` awaits the entire rotation before the mutation resolves and only exposes `persistCallback` (this plan's `persistJob`) as a per-phase hook — first call = root-cut signal, subsequent calls = tail-walk progress. `progress` is wired defensively for forward-compat but the current SDK only ever calls it once (`'rotated'`) at full completion.
- **`resumeInterruptedRotation()` cannot replay a partial walk today** — no SDK entrypoint accepts a pre-seeded job record (every mutation call builds one fresh and empty). This plan delivers the durable checkpoint + `'resuming'` badge signal; actual walk replay is a pre-existing, already-flagged SDK gap for a future plan.
- **Opportunistic reconcile uses the existing `folder:updated` event's `ipnsName`** as "the affected root" — this is the same IPNS name `performScopeExitRotation` rotates for the same mutation, so no new SDK event plumbing was needed.
- **Job-checkpoint storage is a separate IndexedDB database** (`cipherbox-rotation-jobs`) from `rotation-state.service.ts`'s high-water stores — kept within this plan's file scope and structurally distinct (job metadata vs. monotonic-max floors).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Exported `RotationClientCallbacks`/`LocalGrantRecord` from `@cipherbox/sdk`'s public index**

- **Found during:** Task 2 (rotation-driver.service.ts implementation)
- **Issue:** `packages/sdk/src/types.ts` has defined `RotationClientCallbacks`/`LocalGrantRecord` since 68-05, but `packages/sdk/src/index.ts` never re-exported them. `apps/web` only imports the built `@cipherbox/sdk` package (resolved via `dist/index.d.ts`), so `buildRotationClientCallbacks(): RotationClientCallbacks` had no importable return type — a hard blocker for typing the seam's concrete implementation.
- **Fix:** Added `RotationClientCallbacks, LocalGrantRecord` to the existing `export type { ... } from './types'` block in `packages/sdk/src/index.ts`, then rebuilt the `@cipherbox/sdk` dist so `apps/web`'s typecheck picks up the new export.
- **Files modified:** `packages/sdk/src/index.ts`
- **Verification:** `pnpm --filter @cipherbox/web exec tsc --noEmit` passes cleanly after the rebuild.
- **Committed in:** `b559df02a` (Task 2 commit)

**2. [Rule 2 - Missing Critical] Added `runOwnerReconcileForFolder` to `owner-reconcile.service.ts`**

- **Found during:** Task 3 (useAuth.ts wiring)
- **Issue:** The plan's Task 3 acceptance criteria requires the literal string `runOwnerReconcile` inside `useAuth.ts`, and requires the post-mutation trigger to be scoped to "the affected root" while keeping `useAuth.ts` "thin — no rotation/reconcile logic inline". `owner-reconcile.service.ts` (68-07) only exposed `triggerOwnerReconcileOnLogin`, which sweeps ALL sent-grant roots — there was no single-root reconcile function to call, and inlining the `runOwnerReconcile`/transport/job-record construction directly in `useAuth.ts` would have violated the "thin hook" instruction.
- **Fix:** Added `runOwnerReconcileForFolder(rootIpnsName)` to `owner-reconcile.service.ts`, a single-root variant reusing the file's existing `decodeSentGrants`/`makeReconcileJob`/`buildReconcileCtx`/`webOwnerReconcileTransport` helpers verbatim. `useAuth.ts` now calls this one-line wrapper from its `folder:updated` subscription.
- **Files modified:** `apps/web/src/services/owner-reconcile.service.ts` (not in this plan's declared `files_modified`), `apps/web/src/hooks/useAuth.ts`
- **Verification:** `grep -c "runOwnerReconcile" apps/web/src/hooks/useAuth.ts` returns 3; `pnpm --filter @cipherbox/web exec tsc --noEmit` passes.
- **Committed in:** `d3eaa8a19` (Task 3 commit)

---

**Total deviations:** 2 auto-fixed (1 blocking missing-export, 1 missing-critical single-root reconcile function)
**Impact on plan:** Both changes are minimal, additive, and necessary to satisfy this plan's own literal acceptance criteria and artifact contract. Neither touches rotation/reconcile crypto logic — both are export/wiring additions reusing existing, already-reviewed code paths. `owner-reconcile.service.ts` was not in the plan's declared `files_modified` list; flagging for reviewer awareness.

## Known Stubs

None introduced by this plan. `resumeInterruptedRotation()`'s inability to replay a partial walk is NOT a stub in the traditional sense (no hardcoded/empty UI value) — it is a deliberate, documented scope boundary against a pre-existing SDK gap (see Decisions Made above); the badge/checkpoint behavior this plan owns is fully wired and functional.

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: new-crypto-adjacent-storage | `apps/web/src/services/rotation-driver.service.ts` | New IndexedDB database (`cipherbox-rotation-jobs`) storing rotation job checkpoints. Verified metadata-only (rootNodeId/status/completedNodeIds/frontier ipnsNames) — never `frontier[].parentReadKey` or `ipnsPrivateKey` bytes (grep-gated: zero `.fill(0)` calls, and the checkpoint type literal excludes any `Uint8Array` field). Reviewer should confirm this projection stays metadata-only if `RotationJobRecord`'s shape changes in a future plan. |
| threat_flag: first-use-web-api | `apps/web/src/lib/multi-tab-lock.ts` | First use of `navigator.locks` in this codebase (no prior analog). Fallback path (direct call when Web Locks unavailable) is a designed-safe behavior per D-09, not a degraded/insecure mode — confirmed by the module's own security doc comment and the existing idempotent-walk + CAS-409-re-merge guarantees from 68-01/63/64. |

## Issues Encountered

None beyond the two documented deviations above (both self-resolved via Rule 2/Rule 3).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The 68-10 web-e2e rotation-ux spec is the intended real-browser proof point for: (a) badge transitions `root-cut` → `tail-walk` → idle across a real mutation, (b) `'resuming'` badge appearing after a reload mid-walk, and (c) multi-tab leader election not double-driving the same tail walk. No blockers identified for writing that spec against this plan's wiring.
- **Open follow-up (not blocking, flagged for a future plan):** a true resume of an interrupted rotation walk (re-driving `rotateReadFromNode` from a durable `completedNodeIds` seed) requires an SDK-core change — `performScopeExitRotation` currently builds a fresh, empty `RotationJobRecord` on every mutation call, and `verifySubtreeClean`'s own doc comment already flags this as the `rotation-fresh-record-resume-and-sc4-double-bump` gap. This plan's durable checkpoint is ready to be consumed once that SDK entrypoint exists.
- **Open follow-up (not blocking, pre-existing, discovered but out of scope):** after `performScopeExitRotation` rotates a folder's root key, the in-memory `FolderTree` entry's `folderKey` is never updated to the new rotated key (only the on-wire published record advances) — a subsequent mutation on the SAME folder without a reload could use a stale in-memory key. This is a `packages/sdk/src/client.ts` behavior from 68-05, not introduced by this plan, and out of this plan's `apps/web`-only file scope; flagging for a future plan's awareness.

## Self-Check: PASSED

- `apps/web/src/lib/multi-tab-lock.ts` - FOUND
- `apps/web/src/services/rotation-driver.service.ts` - FOUND
- `apps/web/src/hooks/useAuth.ts` - modified, FOUND
- `apps/web/src/services/owner-reconcile.service.ts` - modified, FOUND
- `packages/sdk/src/index.ts` - modified, FOUND
- Commits `e4bddcb52`, `b559df02a`, `d3eaa8a19` - all FOUND in git log
- `pnpm --filter @cipherbox/web exec tsc --noEmit` - PASSED (0 errors)
- `find apps/web/src -name "*.spec.ts"` - empty (no new test files added, per docs/TESTING.md doctrine)

---
*Phase: 68-web-integration-rotation-ux-and-durable-client-state*
*Plan: 08*
*Completed: 2026-07-01*
