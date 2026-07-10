---
phase: 73-shared-write-navigation-correctness-web
plan: 09
subsystem: ui
tags: [react, shared-folder, ipns, playwright, web-e2e]

# Dependency graph
requires:
  - phase: 73-shared-write-navigation-correctness-web (plans 05, 06, 07, 01)
    provides: >
      73-06's consolidated `restoreToBreadcrumbIndex` helper; 73-07's writeKey
      + publishedNode re-seed inside that helper; 73-05's `publishedParent`
      population in `refreshSharedFolder`'s fresh branch; 73-01's fixme SC2
      web-e2e case scaffold.
provides:
  - "SC2: nav-stack restore (navigateUp / navigateToBreadcrumb) re-resolves the target depth via refreshSharedFolder after re-seeding, so a remote mutation to a depth the user navigated away from is no longer served as a permanently-frozen snapshot"
  - "Active (non-fixme) web-e2e case proving SC2 end-to-end with the owner+grantee dual-account harness"
affects: [shared-folder-navigation, shared-folder-projection]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Restore-then-refresh: after seedActiveSharedFolder re-seeds a restored depth, immediately call client.refreshSharedFolder(shareId) as a purely additive re-check, relying on the SDK's own sequenceNumber monotonicity guard rather than adding new invalidation state"

key-files:
  created: []
  modified:
    - apps/web/src/hooks/useSharedNavigationActions.ts
    - tests/web-e2e/tests/shared-folder-desync.spec.ts

key-decisions:
  - "refreshSharedFolder call placed inside restoreToBreadcrumbIndex's existing try/catch (shared by navigateUp and navigateToBreadcrumb) so a refresh failure never undoes the already-committed restore"
  - "No new invalidation data structure -- reuses refreshSharedFolder's existing sequenceNumber monotonicity guard (client.ts:5624) and the already-wired sharedFolder:updated projection subscription"
  - "Item-9 (shared-nav seed race, useSharedNavigation.ts:355-375) re-verified read-only: the listSharedFolder([]) display-projection effect still re-fires via its [currentView, currentShareId, folderChildren, currentSequenceNumber] dependency array whenever the new refreshSharedFolder call causes a sharedFolder:updated emission -- not widened, not touched"

patterns-established:
  - "Additive freshness re-checks are inserted after existing seed/restore steps rather than replacing them, keeping the existing monotonicity guard as the sole anti-rollback mechanism"

requirements-completed: [SC2]

coverage:
  - id: D1
    description: "Restore helper (navigateUp / navigateToBreadcrumb) calls refreshSharedFolder after re-seeding the target depth, additive and monotonicity-guarded"
    requirement: "SC2"
    verification:
      - kind: unit
        ref: "grep -q refreshSharedFolder apps/web/src/hooks/useSharedNavigationActions.ts"
        status: pass
      - kind: integration
        ref: "pnpm --filter @cipherbox/web exec tsc -b"
        status: pass
    human_judgment: false
  - id: D2
    description: "Deeper-mutate-then-navigate-up web-e2e case is active (not fixme) and proves fresh children after a remote mutation to a suspended depth"
    requirement: "SC2"
    verification:
      - kind: e2e
        ref: "tests/web-e2e/tests/shared-folder-desync.spec.ts#Grantee sees fresh children after navigating up following a remote mutation while deeper (SC2)"
        status: pass
    human_judgment: false

duration: 12min
completed: 2026-07-10
status: complete
---

# Phase 73 Plan 09: Nav-Stack Restore Freshness (SC2) Summary

**Restore helper now calls `refreshSharedFolder` after re-seeding, closing the stale-nav-stack-restore gap; new web-e2e case proves it end-to-end (5/5 passing locally).**

## Performance

- **Duration:** ~12 min
- **Completed:** 2026-07-10
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- `restoreToBreadcrumbIndex` (the single helper shared by `navigateUp` and `navigateToBreadcrumb`, consolidated in 73-06 and extended with writeKey/publishedNode re-seeding in 73-07) now calls `getSdkClient().refreshSharedFolder(currentShareId)` immediately after `seedActiveSharedFolder` re-seeds the target depth. This closes SC2: previously, a `sharedFolder:updated` event for a depth the user had navigated away from was silently dropped by the projection subscription (which only ever updates the currently-ACTIVE depth), so restoring that depth replayed the frozen descent-time `children` snapshot forever.
- The fix is purely additive: `refreshSharedFolder` already re-resolves IPNS for the seeded depth and applies its own `state.sequenceNumber >= result.sequenceNumber` monotonicity guard (client.ts:5624) before emitting `sharedFolder:updated` -- no new invalidation data structure was introduced, and the guard is relied on unchanged (no rollback risk).
- Finalized the plan-73-01 `test.fixme` SC2 case in `shared-folder-desync.spec.ts`: grantee descends into a subfolder, the owner mutates the depth left behind (uploads a file into their own copy of the shared folder), the grantee navigates back up, and the test asserts the owner's new file is now visible -- proving the fresh re-resolve, not the frozen snapshot.
- Item-9 (the transient "Shared folder not loaded" seed race in `useSharedNavigation.ts:355-375`, the `listSharedFolder(currentShareId, [])` display-projection effect) was re-verified read-only per the plan's explicit scope boundary: that effect's dependency array (`[currentView, currentShareId, folderChildren, currentSequenceNumber]`) still re-fires whenever the new `refreshSharedFolder` call causes a `sharedFolder:updated` emission (which updates `folderChildren`/`currentSequenceNumber` via the projection subscription). The race is not widened by this change and was left untouched, per the plan's instruction to record rather than fix it here.

## Task Commits

Each task was committed atomically:

1. **Task 1: refreshSharedFolder after re-seed in the restore helper; re-verify seed race** - `af412ad4c` (feat)
2. **Task 2: finalize the SC2 deeper-mutate-then-navigate-up web-e2e case** - `f532081d8` (test)

_Note: this SUMMARY commit follows separately per the worktree execution protocol._

## Files Created/Modified

- `apps/web/src/hooks/useSharedNavigationActions.ts` - `restoreToBreadcrumbIndex` now awaits `getSdkClient().refreshSharedFolder(currentShareId)` after the `seedActiveSharedFolder` call, inside the helper's existing try/catch (a refresh failure is logged and does not undo the already-committed restore).
- `tests/web-e2e/tests/shared-folder-desync.spec.ts` - Removed the plan-73-01 `test.fixme` guard from the deeper-mutate-then-navigate-up SC2 case; it is now an active, passing test in the `describe.serial` suite.

## Decisions Made

- Placed the `refreshSharedFolder` call inside the restore helper's existing try/catch rather than adding a separate try/catch, matching the plan's instruction that a refresh failure must not break the already-committed restore.
- Did not touch `useSharedNavigation.ts` (item-9's seed-race effect) -- explicitly out of scope per the plan; re-verify-only.

## Deviations from Plan

None - plan executed exactly as written. No new dependencies, no architectural changes, no bespoke invalidation logic added.

## Issues Encountered

None. Local `.env` files (`apps/api/.env`, `apps/web/.env`, `tests/web-e2e/.env`) were absent in this fresh worktree checkout (gitignored) and were copied from the main tree to align `TEST_LOGIN_SECRET` with the already-running local API/docker stack, per established project convention for worktree-based E2E runs -- no code or config changes resulted from this, and the copied files remain untracked/gitignored.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SC2 is closed: nav-stack restore now reflects fresh children after a remote mutation to a suspended depth, additive to existing freshness machinery and monotonicity-guarded.
- `apps/web` typechecks clean (`pnpm --filter @cipherbox/web exec tsc -b`); the web-e2e spec typechecks clean (`pnpm --filter @cipherbox/web-e2e exec tsc --noEmit`) and lists correctly via `playwright test --list`.
- Full local run of `shared-folder-desync.spec.ts` against the docker stack: 5/5 tests passing, including the new SC2 case (58.0s total).
- No known follow-ups from this plan; item-9's seed race remains a pre-existing, lower-priority, explicitly-deferred item unaffected by this change.

---
*Phase: 73-shared-write-navigation-correctness-web*
*Completed: 2026-07-10*
