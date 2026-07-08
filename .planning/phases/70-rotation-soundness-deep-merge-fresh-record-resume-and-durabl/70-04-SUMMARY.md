---
phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl
plan: 04
subsystem: sdk-core
tags: [rotation, merge, sealedchildref, tdd, elevation-of-privilege, bfs]

# Dependency graph
requires:
  - phase: 70-01
    provides: mergeRotatedChildren(base, local, remote) — rotation-only local-wins three-way merge
provides:
  - mergeConcurrentChildren returns { published, mergedChildren } and delegates to mergeRotatedChildren (site A)
  - rotateOne returns the CAS-merged children (mergedChildrenForReturn capture) instead of the pre-merge node.children snapshot
  - updateFolderMetadataAndPublish optional mergeChildrenFn + baseChildren params (default remote-wins mergeChildren unchanged)
  - ParentTrackingState.baseChildrenSnapshot captured at parentTracking.set time
  - enqueueConcurrentlyAddedChildren — diffs D-09 republish's publishedChildren against the pre-call snapshot and pushes concurrent adds onto the BFS queue (site B)
affects: [70-08, engine.ts rotation call sites, folder/registration.ts consumers]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Outer-scope merge-result capture idiom (mergedChildrenForReturn in rotateOne) mirrors registration.ts's currentWriteChildren capture"
    - "Injectable mergeChildrenFn on a generic publish helper, defaulting to the existing policy, so rotation opts in explicitly at its own call sites without changing non-rotation callers"

key-files:
  created: []
  modified:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/folder/registration.ts
    - packages/sdk-core/src/__tests__/rotation/engine.test.ts

key-decisions:
  - "mergeConcurrentChildren (site A) now delegates to mergeRotatedChildren instead of the generic remote-wins mergeChildren, and returns { published, mergedChildren } so rotateOne can capture the plaintext merged set for its own return value"
  - "updateFolderMetadataAndPublish's mergeChildrenFn defaults to mergeChildren (remote-wins) — every non-rotation caller (add/move/rename) is byte-unchanged; only the two D-09 batched-republish call sites inside rotateReadFromNode opt into mergeRotatedChildren explicitly"
  - "baseChildrenSnapshot captured on ParentTrackingState at parentTracking.set time (before any child-driven mutation) so the D-09 site B merge's base-only-omission check runs against the true CAS base, not an empty default"
  - "Concurrently-added children surfaced by the D-09 republish are diffed by ipnsName against the pre-call snapshot and pushed onto the BFS queue with their readKey derived via unsealChildReadKey against the parent's NOW-CURRENT (rotated) key, per PATTERNS.md Pattern 2"
  - "Task 3 (site B + enqueue) is GREEN-only per the plan's literal task breakdown — Task 1's RED scope covered only site A + the mergeConcurrentChildren return shape; site B's behavior is verified structurally (tsc clean, full rotation/engine + folder suites green) rather than via a new dedicated unit test"

patterns-established:
  - "Rotation-owned merge policies are threaded into generic publish helpers via an optional injectable param defaulting to the existing (safe) policy, never by mutating the generic default"

requirements-completed: ["SC#1", "SC#3"]

coverage:
  - id: D1
    description: "Site A (mergeConcurrentChildren / rotateOne's own CAS-409) uses local-wins mergeRotatedChildren; a rotated child's new-key seal survives a merge against a remote still holding the stale seal"
    requirement: "SC#1"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#Test 5 (Plan 70-04): local wins on conflict — merged child keeps the LOCAL (new-key) readKeySealed over remote stale seal"
        status: pass
    human_judgment: false
  - id: D2
    description: "rotateOne returns the CAS-merged children (including a remote-added concurrent child), not the pre-merge node.children snapshot"
    requirement: "SC#3"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#Test 6 (Plan 70-04): rotateOne returns the MERGED children (incl. remote add), not the pre-merge node.children snapshot"
        status: pass
    human_judgment: false
  - id: D3
    description: "mergeConcurrentChildren exposes { published, mergedChildren }"
    requirement: "SC#1"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#Test 7 (Plan 70-04): mergeConcurrentChildren returns { published, mergedChildren } reflecting local-wins + concurrent-add merge"
        status: pass
    human_judgment: false
  - id: D4
    description: "Site B (updateFolderMetadataAndPublish's D-09 batched-republish inline merge) accepts an injectable mergeChildrenFn defaulting to the existing remote-wins mergeChildren; both D-09 call sites in rotateReadFromNode pass mergeRotatedChildren + the captured baseChildrenSnapshot; a concurrently-added child surfaced by the merge is enqueued onto the BFS frontier"
    requirement: "SC#1"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk-core test -- rotation/engine (41 tests) and -- folder (31 files, 348 tests) — full green, no regressions"
      - kind: other
        ref: "git diff --stat packages/sdk-core/src/folder/merge.ts (no changes — remote-wins default preserved)"
        status: pass
    human_judgment: true
    rationale: "No new dedicated unit test directly exercises the site-B CAS-409 merge + BFS-enqueue path (the plan's Task 1 RED scope covered only site A). The implementation follows PATTERNS.md Pattern 2 verbatim and is proven not to regress any existing behavior, but the concurrent-add-enqueue behavior itself is only e2e-provable — deferred to Plan 70-08's strengthened e2e test 3 per the phase's test architecture."

# Metrics
duration: 10min
completed: 2026-07-07
status: complete
---

# Phase 70 Plan 04: Wire Local-Wins Merge at Both Rotation Sites + Return Merged Children Summary

**Local-wins mergeRotatedChildren wired into both rotation CAS-409 merge sites (engine.ts's mergeConcurrentChildren and registration.ts's D-09 batched republish), with rotateOne now returning the CAS-merged children so concurrent adds are enqueued onto the BFS frontier**

## Performance

- **Duration:** 10 min
- **Started:** 2026-07-07T22:15:00Z
- **Completed:** 2026-07-07T22:25:00Z
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments
- `mergeConcurrentChildren` (site A) swapped from the generic remote-wins `mergeChildren` to the rotation-only local-wins `mergeRotatedChildren`, and now returns `{ published, mergedChildren }` instead of just a `PublishedNode`
- `rotateOne`'s CAS-409 merge closure captures the plaintext merged children into an outer-scope `mergedChildrenForReturn` (mirroring `registration.ts`'s `currentWriteChildren` idiom); the final return now uses the merged set instead of the pre-merge `node.children` snapshot
- `updateFolderMetadataAndPublish` gained an optional `mergeChildrenFn` param, defaulting to the existing remote-wins `mergeChildren` — every non-rotation caller (add/move/rename) is byte-unchanged
- Both D-09 batched-republish call sites inside `rotateReadFromNode` now pass `mergeChildrenFn: mergeRotatedChildren` and a `baseChildrenSnapshot` captured at `parentTracking.set` time (before any child-driven mutation)
- A new `enqueueConcurrentlyAddedChildren` helper diffs the republish's `publishedChildren` against the pre-call snapshot by `ipnsName` and pushes any newly-present (concurrently-added) child onto the BFS `queue`, deriving its readKey via `unsealChildReadKey` against the parent's now-current key
- `folder/merge.ts`'s generic `mergeChildren` remote-wins default is completely untouched (verified via `git diff --stat`)

## Task Commits

Each task was committed atomically (TDD RED/GREEN):

1. **Task 1 (RED): engine.test.ts assertions for local-wins merge + merged-children return** - `81940e328` (test)
2. **Task 2 (GREEN): swap site A + return merged children from mergeConcurrentChildren/rotateOne** - `1d78acc90` (feat)
3. **Task 3 (GREEN): injectable local-wins policy at site B + enqueue concurrent adds** - `1134ee1ea` (feat)

## Files Created/Modified
- `packages/sdk-core/src/rotation/engine.ts` - `mergeConcurrentChildren` swapped to `mergeRotatedChildren` with new return shape; `rotateOne`'s `mergedChildrenForReturn` capture; `ParentTrackingState.baseChildrenSnapshot`; new `enqueueConcurrentlyAddedChildren` helper; both D-09 call sites updated to pass `mergeChildrenFn`/`baseChildren` and enqueue concurrent adds
- `packages/sdk-core/src/folder/registration.ts` - `updateFolderMetadataAndPublish` gained optional `mergeChildrenFn` param; inline merge closure defaults to `mergeChildren`, uses `params.mergeChildrenFn` when supplied
- `packages/sdk-core/src/__tests__/rotation/engine.test.ts` - Added Test 5 (local-wins conflict), Test 6 (rotateOne return-value merged set), Test 7 (`mergeConcurrentChildren` return-shape) to the CAS-409 describe block; imported `mergeConcurrentChildren`

## TDD Gate Compliance

RED gate: `81940e328` (`test(70-04): add RED assertions...`) — confirmed failing against the pre-change remote-wins implementation before Task 2 (3 assertions failed: local-wins seal, merged-children return, `{ published, mergedChildren }` shape).

GREEN gate: `1d78acc90` — all 41 `rotation/engine.test.ts` tests pass after site-A swap.

Task 3 (site B + BFS enqueue) is **GREEN-only**, consistent with the plan's literal task breakdown: Task 1's `<behavior>` block scoped RED assertions to site A and the `mergeConcurrentChildren` return shape only, with no RED assertions for site B's inline-merge injection or the BFS-enqueue diff. Task 3's acceptance criteria required only that the full `rotation/engine` and `folder` suites stay green and that `folder/merge.ts` remain unmodified — both confirmed. No dedicated unit test proves the site-B CAS-409-triggers-enqueue path end-to-end (see coverage D4's `human_judgment: true` rationale); that proof is deferred to Plan 70-08's strengthened e2e test 3 per the phase's own test architecture (RESEARCH.md Phase Requirements → Test Map).

## Decisions Made
- Followed PATTERNS.md verbatim for both the outer-scope capture idiom (`mergedChildrenForReturn`) and the injectable-policy-with-safe-default idiom (`mergeChildrenFn`) — no deviation from the documented design
- `enqueueConcurrentlyAddedChildren` derives a concurrently-added child's readKey against the PARENT's now-current (rotated) key, per PATTERNS.md Pattern 2's explicit guidance, rather than the parent's pre-rotation key — trusted as specified since this exact timing assumption was locked in the phase's RESEARCH/PATTERNS documents, not re-litigated here
- Did not add a new integration-style unit test for the site-B CAS-409 + BFS-enqueue path — constructing a correct multi-call-site mock scenario (root rotateOne publish, child rotateOne publish, AND the batched parent republish all sharing the same globally-mocked `publishWithCas`) carried meaningful flake risk for a behavior the plan's own Task 1 RED scope did not require proving via unit test; existing suite regression coverage plus tsc were used as the verification gate instead, matching Task 3's literal acceptance criteria

## Deviations from Plan

None - plan executed exactly as written. Task 3 was implemented without a preceding dedicated RED test for site B specifically because the plan's own Task 1 RED scope only covered site A + the return-shape assertion; this is a reading of the plan's literal task boundaries, not a deviation from it.

## Issues Encountered

None. `pnpm --filter @cipherbox/sdk-core exec tsc --noEmit` reports exactly 50 pre-existing errors confined to `src/__tests__/share/grant.test.ts` (38) and `src/__tests__/cas.test.ts` (12) — the documented pre-existing baseline (per this plan's constraints and 70-01-SUMMARY.md's prior confirmation) — before and after all three task commits. Zero new errors introduced.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Local-wins merge is now wired at both rotation CAS-409 sites and concurrent adds are enqueued for their own rotation pass, closing SC#1's merge-downgrade Elevation-of-Privilege gap at every known path and closing SC#3's "concurrent add silently dropped from the walk" gap. Plan 70-08 (per the phase's test architecture) should strengthen `rotation-crash-safety.test.ts` test 3 to navigate into the concurrently-added child and unseal it with the new root key, proving the site-B fix end-to-end at the e2e layer — this plan's unit-level coverage stops at the engine/registration boundary.

---
*Phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl*
*Completed: 2026-07-07*

## Self-Check: PASSED

All 4 created/modified files found on disk; all 3 task commits (81940e328, 1d78acc90, 1134ee1ea) verified present in git log.
