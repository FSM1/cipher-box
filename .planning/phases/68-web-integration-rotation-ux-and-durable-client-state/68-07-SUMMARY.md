---
phase: 68-web-integration-rotation-ux-and-durable-client-state
plan: 07
subsystem: sdk
tags: [rotation, sharing, ecies, vitest, react, owner-reconcile]

# Dependency graph
requires:
  - phase: 65-sdk-write-chain-bin-re-link-and-invite-claim
    provides: "reMintGrantsRootedAt (sdk-core, mock-tested) + the D-01/Q3 owner-reconcile authority decision"
  - phase: 68 (plan 02)
    provides: "useAuth.ts vault/SDK init flow (login trigger insertion point)"
  - phase: 68 (plan 03)
    provides: "PATCH /shares/:shareId/grant + sharesControllerUpdateGrant api-client method"
provides:
  - "packages/sdk/src/share/owner-reconcile.ts: buildGrantRemintCallbacks(transport) + runOwnerReconcile, unit-tested"
  - "apps/web/src/services/owner-reconcile.service.ts: thin api-client transport + DTO decode"
  - "Eager owner-reconcile trigger wired into useAuth.ts (D-11 login/app-open cadence)"
affects: ["68-08 (post-mutation opportunistic reconcile trigger)"]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Injected-transport driver seam (mirrors rotation engine's GrantRemintCallbacks / WriteRevocationCallbacks pattern): SDK owns the testable branch logic, apps/web supplies only the concrete api-client calls"
    - "Structural type extraction (NonNullable<Parameters<typeof fn>[n]>) to consume a non-exported sdk-core type without adding a new sdk-core barrel export"

key-files:
  created:
    - packages/sdk/src/share/owner-reconcile.ts
    - packages/sdk/src/__tests__/owner-reconcile.test.ts
    - apps/web/src/services/owner-reconcile.service.ts
  modified:
    - packages/sdk/src/share/index.ts
    - packages/sdk/src/index.ts
    - apps/web/src/hooks/useAuth.ts

key-decisions:
  - "GrantRemintCallbacks type consumed via NonNullable<Parameters<typeof reMintGrantsRootedAt>[5]> instead of adding a new sdk-core barrel export -- avoids expanding sdk-core's public surface for a type that already matches structurally"
  - "Web transport's isRevoked always decodes to false: this project's shares table uses hard-delete revocation (revoke = DELETE, never a soft revoked_at flag per project convention), so GET /shares/sent can never return an already-revoked row -- there is no soft-revoked state to decode from the DTO"
  - "Eager login-time reconcile sweeps distinct sent-grant rootNodeIds and resolves each root's current readKey/generation from the SDK's already-loaded in-memory FolderTree (keyed by rootIpnsName from the DTO); roots not yet loaded are skipped as best-effort (no schema/tree-walk changes) -- the 68-08 post-mutation trigger covers the live, freshly-rotated case with a guaranteed-available readKey"

requirements-completed: [ROT-07]

coverage:
  - id: D1
    description: "SDK owner-reconcile driver (buildGrantRemintCallbacks + runOwnerReconcile) drives reMintGrantsRootedAt: revoked grant -> deleteGrant only, surviving grant -> updateGrant only, rootNodeId filter drops non-matching grants"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/owner-reconcile.test.ts#buildGrantRemintCallbacks queryGrantsFn filters transport.listSentGrants() by rootNodeId"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/owner-reconcile.test.ts#runOwnerReconcile revoked grant -> transport.deleteGrant called, transport.updateGrant NOT called"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/owner-reconcile.test.ts#runOwnerReconcile surviving grant -> transport.updateGrant called, transport.deleteGrant NOT called"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/owner-reconcile.test.ts#runOwnerReconcile non-matching rootNodeId grants are dropped"
        status: pass
    human_judgment: false
  - id: D2
    description: "apps/web owner-reconcile.service.ts is a thin, untested api-client transport wrapper (GET sent shares / PATCH grant / DELETE share) delegating all branch logic to the SDK driver; wired to run eagerly on login/app-open from useAuth.ts without blocking the login return path"
    requirement: "ROT-07"
    verification:
      - kind: other
        ref: "pnpm --filter @cipherbox/web exec tsc --noEmit (clean); grep acceptance criteria in 68-07-PLAN.md Task 2 (api-client symbol count, runOwnerReconcile delegation, useAuth wiring, zero new apps/web test/spec files)"
        status: pass
    human_judgment: true
    rationale: "The eager login-sweep's FolderTree-lookup heuristic (best-effort, skips unloaded roots) and the fire-and-forget non-blocking behavior in useAuth.ts are runtime/UX properties that static analysis and greps cannot fully confirm -- needs a human login-flow smoke check per project doctrine (apps/web is untested by design; see docs/TESTING.md)."

duration: 15min
completed: 2026-07-01
status: complete
---

# Phase 68 Plan 07: Q3 Owner-Reconcile Authority Mirror Summary

**SDK-hoisted owner-reconcile driver (unit-tested Vitest transport seam) plus a thin, untested apps/web api-client wrapper wired to run eagerly on login (D-10/D-11).**

## Performance

- **Duration:** 15 min
- **Started:** 2026-07-01T19:02:53+02:00
- **Completed:** 2026-07-01T19:16:42+02:00
- **Tasks:** 2 (Task 1 TDD RED+GREEN, Task 2 execute)
- **Files modified:** 6 (3 created, 3 modified)

## Accomplishments
- `packages/sdk/src/share/owner-reconcile.ts` exports `buildGrantRemintCallbacks(transport)` (assembles sdk-core's `GrantRemintCallbacks` from an injected `OwnerReconcileTransport`, client-side-filtering `listSentGrants()` by `rootNodeId` per RESEARCH A3) and `runOwnerReconcile(...)` (drives `reMintGrantsRootedAt`), unit-tested with a `vi.fn()` transport covering the revoked-delete-only, surviving-update-only, and rootNodeId-filter branches
- `apps/web/src/services/owner-reconcile.service.ts` supplies the concrete api-client transport (`sharesControllerGetSentShares` / `sharesControllerUpdateGrant` / `sharesControllerRevokeShare`) and DTO decode, with zero inline branch logic (thin wrapper per docs/TESTING.md doctrine, no unit test added)
- `useAuth.ts` fires `triggerOwnerReconcileOnLogin()` eagerly, fire-and-forget, after vault/SDK init completes -- the D-11 login/app-open cadence
- Barrel exports added at `packages/sdk/src/share/index.ts` and `packages/sdk/src/index.ts`

## Task Commits

Each task was committed atomically (Task 1 is TDD: RED then GREEN):

1. **Task 1 RED: failing test for owner-reconcile driver** - `d14844ff8` (test)
2. **Task 1 GREEN: SDK owner-reconcile driver implementation** - `a383133f3` (feat)
3. **Task 2: web thin transport wrapper + eager login trigger** - `9476cbb8c` (feat)

_No plan-metadata commit in this SUMMARY -- STATE.md/ROADMAP.md updates are owned by the wave orchestrator per this plan's parallel-executor contract._

## Files Created/Modified
- `packages/sdk/src/share/owner-reconcile.ts` - `buildGrantRemintCallbacks(transport)` + `runOwnerReconcile(...)`, the unit-tested SDK driver
- `packages/sdk/src/__tests__/owner-reconcile.test.ts` - Vitest coverage (4 tests): rootNodeId filter, revoked -> delete-only, surviving -> update-only, non-matching-root drop
- `packages/sdk/src/share/index.ts` - re-exports the new driver surface
- `packages/sdk/src/index.ts` - top-level barrel re-export of the driver surface
- `apps/web/src/services/owner-reconcile.service.ts` - concrete api-client transport, DTO decode, `triggerOwnerReconcileOnLogin()`
- `apps/web/src/hooks/useAuth.ts` - fire-and-forget eager reconcile call after vault/SDK init

## Decisions Made
- **`GrantRemintCallbacks` type extraction without a new sdk-core export:** sdk-core's package.json only publishes a single `.` export path and does not export `GrantRemintCallbacks` by name from its barrel. Rather than adding a new sdk-core export surface for a Phase-68 web-integration plan, the SDK driver derives the callbacks type structurally via `NonNullable<Parameters<typeof reMintGrantsRootedAt>[5]>` -- TypeScript's structural typing satisfies the same contract with zero sdk-core changes.
- **`isRevoked` always `false` in the web transport:** confirmed against `SentShareResponseDto` (no `isRevoked`/`revokedAt` field exists) and the project's documented hard-delete revocation convention (revoke = DELETE the row, never a soft flag). A revoked grant is therefore never returned by `GET /shares/sent` in the first place -- the delete-branch of `reMintGrantsRootedAt` stays structurally wired (and unit-tested at the SDK tier) but is not expected to fire from this concrete transport under the current DB model. Documented in-code so future readers don't mistake this for a missing decode.
- **Eager login sweep scoped to already-loaded `FolderTree` entries:** rather than force-loading every distinct shared root at login (out of scope, no schema/tree-walk work specified by the plan), the sweep looks up each root's current `folderKey`/`nodeGeneration` via the SDK's in-memory `FolderTree.get(rootIpnsName)` and skips roots not yet loaded. This is best-effort by design -- the 68-08 post-mutation trigger fires immediately after the owner's own rotation with a guaranteed fresh `newReadKey`, closing the gap for the live case.

## Deviations from Plan

None - plan executed exactly as written. The `GrantRemintCallbacks`-type-extraction and `isRevoked`-always-false decisions above are implementation choices made while following the plan's stated action items (which explicitly said "decode recipientPublicKey per the DTO encoding — confirm via the model" and left the exact `isRevoked` source for interpretation); no plan-deviation rule (auto-fix, blocking issue, or architectural change) was triggered.

## Issues Encountered
- **Cross-package dist staleness (pre-existing, not introduced by this plan):** the worktree's `node_modules` had no built `dist/` for `@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/sdk-core`, or `@cipherbox/api-client`, causing `pnpm --filter @cipherbox/sdk exec vitest run` to fail with a Vite package-entry-resolution error unrelated to this plan's code. Rebuilt all four packages (`pnpm --filter <pkg> build`) before running tests; this is a known project gotcha (see `project-cross-package-dist-staleness` in project memory), not a plan defect.
- **Worktree cwd drift:** an early `cd <absolute-main-repo-path> && ...` command drifted the shell into the shared main-repo checkout instead of the worktree (caught via the `owner-reconcile.test.ts` file-not-found error pointing at the wrong root). Recovered by re-deriving `WT_ROOT` from `git rev-parse --show-toplevel` and re-running all subsequent commands with that absolute path; no files were written to the main-repo checkout.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- The `OwnerReconcileTransport` seam and `runOwnerReconcile` entry point are ready for 68-08 to call from the post-mutation event handler with a freshly-rotated `newReadKey`/`newGeneration` (no further SDK changes needed for that wiring).
- `packages/sdk` build (`tsup && tsc`) and the full non-integration Vitest suite (252 passed, 46 skipped) are green with these changes; `apps/web` `tsc --noEmit` is clean.
- No blockers. The eager login sweep's "unloaded root is skipped" limitation is a known, documented best-effort gap (not a stub in the Known Stubs sense -- it degrades gracefully to "reconcile happens on next opportunistic post-mutation trigger" rather than rendering broken/empty UI).

## Self-Check: PASSED

All created files and task commit hashes verified present on disk / in git history:
- `packages/sdk/src/share/owner-reconcile.ts` - FOUND
- `packages/sdk/src/__tests__/owner-reconcile.test.ts` - FOUND
- `apps/web/src/services/owner-reconcile.service.ts` - FOUND
- `.planning/phases/68-web-integration-rotation-ux-and-durable-client-state/68-07-SUMMARY.md` - FOUND
- `d14844ff8` (test RED), `a383133f3` (feat GREEN), `9476cbb8c` (feat web wrapper) - all FOUND in git log

---
*Phase: 68-web-integration-rotation-ux-and-durable-client-state*
*Completed: 2026-07-01*
