---
phase: 73-shared-write-navigation-correctness-web
plan: 05
subsystem: sdk
tags: [ipns, shared-write, tombstone, anti-rollback, vitest]

requires:
  - phase: 73-02
    provides: "createAndPublishIpnsRecord returns { tombstoned?: boolean } on a 410 IPNS response"
provides:
  - "publishNodeFn (buildWriteTransportSeams) surfaces a real tombstone signal to shared-write.ts's existing CannotWriteUntilRefetchError throw sites"
  - "refreshSharedFolder's fresh branch keeps the write-body's cached publishedNode fresh via an extra resolvePublishedNode round trip"
affects: [73-08, 73-09]

tech-stack:
  added: []
  patterns: []

key-files:
  created: []
  modified:
    - packages/sdk/src/client.ts
    - packages/sdk/src/__tests__/client-shared-write.test.ts

key-decisions:
  - "publishNodeFn checks pubResult.tombstoned BEFORE the generic !pubResult.success throw, since a tombstone is a specific retryable-after-refetch signal, not a generic publish failure"
  - "refreshSharedFolder's fresh branch adds a second resolvePublishedNode(state.ipnsName) call (extra IPFS+IPNS round trip) rather than changing loadFolderMetadata's return shape, per 73-RESEARCH.md's recommended bounded-cost approach"

patterns-established: []

requirements-completed: [SC4, SC2]

coverage:
  - id: D1
    description: "publishNodeFn returns { tombstoned: true } when sdkCore.createAndPublishIpnsRecord reports a tombstone, giving shared-write.ts's CannotWriteUntilRefetchError throw sites a live source (SC4 gap b)"
    requirement: "SC4"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk test (full suite, 420 tests) + pnpm --filter @cipherbox/sdk exec tsc --noEmit"
        status: pass
    human_judgment: false
  - id: D2
    description: "refreshSharedFolder's fresh branch populates publishedParent via resolvePublishedNode(state.ipnsName), keeping the write-body's cached envelope fresh (SC2 item-4), without weakening the sequenceNumber monotonicity guard"
    requirement: "SC2"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/client-shared-write.test.ts#refreshSharedFolder > adopts a newer resolved sequence into sharedFolderTree and emits sharedFolder:updated"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-10
status: complete
---

# Phase 73 Plan 05: Tombstone-Aware publishNodeFn and Fresh-Envelope refreshSharedFolder Summary

**publishNodeFn now maps createAndPublishIpnsRecord's tombstoned field through to shared-write.ts's existing throw sites, and refreshSharedFolder's fresh branch re-resolves the raw PublishedNode envelope so the write-body's cached publishedParent never goes stale.**

## Performance

- **Duration:** 25 min
- **Started:** 2026-07-10T19:09:16Z
- **Completed:** 2026-07-10T19:37:57Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- `publishNodeFn` (client.ts `buildWriteTransportSeams`) now checks `pubResult.tombstoned === true` immediately after `sdkCore.createAndPublishIpnsRecord` and returns `{ tombstoned: true }` before the generic `!pubResult.success` throw — `shared-write.ts`'s three `CannotWriteUntilRefetchError` throw sites (238/362/505) now have a real upstream signal instead of never firing.
- `refreshSharedFolder`'s fresh branch (only reached when the sequenceNumber monotonicity guard has NOT short-circuited) now calls `this.resolvePublishedNode(state.ipnsName)` and passes the result through as `publishedParent` to `adoptSharedFolderResult`, closing coderabbit-backlog item 4 — a later shared write signs against the just-refreshed envelope instead of a stale one.

## Task Commits

Each task was committed atomically:

1. **Task 1 (SC4b): map createAndPublishIpnsRecord.tombstoned through publishNodeFn** - `0b5d0f957` (feat)
2. **Task 2 (SC2 item-4): populate publishedParent in refreshSharedFolder's fresh branch** - `3a78c1c48` (feat)

_No plan-metadata docs commit in this worktree — the orchestrator handles STATE.md/ROADMAP.md updates after merge._

## Files Created/Modified

- `packages/sdk/src/client.ts` - `publishNodeFn` tombstone mapping (Task 1); `refreshSharedFolder`'s fresh branch resolves and forwards `publishedParent` (Task 2)
- `packages/sdk/src/__tests__/client-shared-write.test.ts` - added `resolveIpnsRecord`/`fetchFromIpfs` mocks to the sdk-core mock and updated the "adopts a newer resolved sequence" test to mock the additional envelope resolve and assert `publishedNode` propagation

## Decisions Made

- `publishNodeFn` checks `pubResult.tombstoned` before the generic success check — a tombstone is a specific, retryable-after-refetch signal, not a generic publish failure, and must not be masked by the generic throw.
- Chose the `resolvePublishedNode`-based fix for SC2 item-4 (extra IPFS+IPNS round trip) over changing `loadFolderMetadata`'s return shape, per 73-RESEARCH.md's recommendation — bounded cost, no change to a shared lower-level function's contract.
- Left the stale/no-op branch of `refreshSharedFolder` (lines above the guard) and the sequenceNumber monotonicity guard itself completely untouched, per the plan's explicit constraint.

## Deviations from Plan

None - plan executed exactly as written. The plan's own acceptance criteria anticipated the test-mock update needed for Task 2 ("If this added resolve breaks any refreshSharedFolder-related test mock... update that test's mocks to expect the additional resolve") — the actually-affected file was `client-shared-write.test.ts` (not `folder-reresolve.test.ts`, which tests `ensureFolderLoaded`, a different method never touched by this plan). Updated its `sdk-core` mock and the one fresh-branch test case accordingly; no assertions were weakened.

## Issues Encountered

None beyond the anticipated test-mock update described above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SC4 gap (b) and SC2 item-4 both closed; `publishNodeFn` and `refreshSharedFolder` are ready for 73-08's e2e proof (which exercises `publishNodeFn`'s tombstone mapping end-to-end) and 73-09 (which raises `refreshSharedFolder`'s call frequency on restore — the now-fresh `publishedParent` prevents that higher frequency from widening the write-body staleness window).
- Full `packages/sdk` suite green: 420 passed, 3 skipped (live-API integration suite, expected without a local API), 1 skipped file.
- `packages/sdk` typecheck clean (`tsc --noEmit`).
- `shared-write.ts` verified untouched via `git diff --stat`; no `axios` import added to `packages/sdk`.

---

*Phase: 73-shared-write-navigation-correctness-web*
*Completed: 2026-07-10*

## Self-Check: PASSED

- FOUND: .planning/phases/73-shared-write-navigation-correctness-web/73-05-SUMMARY.md
- FOUND commit: 0b5d0f957
- FOUND commit: 3a78c1c48
- FOUND commit: 2e192ad94
