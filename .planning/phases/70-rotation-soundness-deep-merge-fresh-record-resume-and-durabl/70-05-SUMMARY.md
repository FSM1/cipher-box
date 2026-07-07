---
phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl
plan: 05
subsystem: sdk-core
tags: [rotation, verifySubtreeClean, dirty-frontier, recursion, elevation-of-privilege, crash-recovery]

# Dependency graph
requires:
  - phase: 70-04
    provides: rotateOne returns CAS-merged children; mergeConcurrentChildren local-wins merge sites wired
provides:
  - verifySubtreeClean recurses the FULL subtree (not just root's immediate children), resolving every node's published IPNS record at any depth
  - A missing root IPNS record is surfaced as isDirty:true (never silently isDirty:false)
  - DirtyFrontierItem — richer frontier item shape { ipnsName, nodeId, parentIpnsName, nodeReadKey, childPubKind, enqueuedGeneration } carrying an engine-derived key so a dirty node at any depth can seed a BFS directly
  - resolveAndFetchNode / resolveChildKeyAndEnvelope — shared key-chain-walk helpers used by both verifySubtreeClean and rotateReadFromNode's main BFS (four previously-duplicated resolve+unseal call sites deduplicated)
affects: [70-06, engine.ts rotation call sites]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Recursion only descends below a CLEAN edge (parent-mirror generation matches published generation) — a dirty edge's derived key is provably the child's stale pre-rotation key and cannot unseal its current body, so recursion stops there and the BFS convergence-guard witness-refresh resolves it on resume"
    - "Shared key-chain-walk helper (resolveChildKeyAndEnvelope) used by both a read-only recursive walk and a mutating BFS, eliminating duplicate resolve+unseal implementations"

key-files:
  created: []
  modified:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/__tests__/rotation/engine.test.ts

key-decisions:
  - "verifySubtreeClean's return frontier item shape changed from { ipnsName, nodeId } to DirtyFrontierItem { ipnsName, nodeId, parentIpnsName, nodeReadKey, childPubKind, enqueuedGeneration } per RESEARCH.md Pitfall 3 — the consumer no longer needs to re-derive keys assuming depth-1. Consumption/wiring of the new fields into rotateReadFromNode's dirty-resume seeding block is deferred to plan 70-06 (fresh-record resume) per this plan's own objective text; the existing consumer code still compiles unchanged (structural typing) and its behavior is unaffected by this plan"
  - "A missing root record returns { isDirty: true, frontier: [] } rather than throwing directly — the existing downstream caller (rotateReadFromNode's dirty-resume block) already re-resolves the root itself on the isDirty:true path and throws a descriptive, actionable error when it too finds the root missing, so no duplicate error-surfacing logic was added"
  - "Recursion into a child only proceeds when childPub.kind === 'folder' AND the edge is clean (childPub.generation === childRef.generation) — a dirty edge is recorded in the frontier and NOT recursed into further, since its derived readKey comes from the still-unrefreshed parent mirror and cannot unseal the child's current published body (no cryptographic recovery path for a key genuinely lost to an interrupted prior run, per RESEARCH.md Pitfall 4)"
  - "Extracted resolveAndFetchNode and resolveChildKeyAndEnvelope as shared module-level helpers, then refactored rotateReadFromNode's four existing duplicate resolve+unseal call sites (enqueueConcurrentlyAddedChildren, dirty-resume frontier seeding, root's-children enqueue, grandchildren enqueue) to use resolveChildKeyAndEnvelope — a pure mechanical dedup with no behavior change, satisfying the plan's 'no duplicated key-chain-walk' prohibition"
  - "Adjusted two pre-existing depth-1 verifySubtreeClean/rotateReadFromNode test fixtures (their clean child edges defaulted to kind 'folder') to mark the child as kind 'file' — the new recursion would otherwise attempt to descend into them against a static unsealNode mock returning the same root node for every call, hanging the suite. This is a test-infrastructure fix required by the recursion behavior itself, not a scope change"

patterns-established:
  - "verifySubtreeClean's docstring documents full-subtree recursion and the crypto-grounded reason recursion stops below a dirty edge; the stale 'not yet wired — needs the Phase-68 durable client floor' claim (which referred to a different, still-open problem — see RESEARCH.md Pitfall 4 / Open Question 1) is removed"

requirements-completed: ["SC#2"]

coverage:
  - id: D1
    description: "verifySubtreeClean recurses into clean folder children to find dirty edges at depth 2 (grandchild), returning a frontier item with an engine-derived nodeReadKey, parentIpnsName, childPubKind, and enqueuedGeneration"
    requirement: "SC#2"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#Test 1 (Plan 70-05): dirty at depth 2 — grandchild dirty edge carries a usable engine-derived nodeReadKey"
        status: pass
    human_judgment: false
  - id: D2
    description: "A missing root IPNS record is treated as dirty (isDirty: true), never silently short-circuited to clean"
    requirement: "SC#2"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#Test 2 (Plan 70-05): missing root IPNS record surfaces as dirty, never silently clean"
        status: pass
    human_judgment: false
  - id: D3
    description: "A fully-clean multi-level tree (root -> subfolder -> grandchild, all generations matching) returns isDirty: false with an empty frontier"
    requirement: "SC#2"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#Test 3 (Plan 70-05): clean multi-level tree — no dirty edges at any depth returns isDirty false"
        status: pass
    human_judgment: false
  - id: D4
    description: "A single shared key-chain-walk helper (resolveChildKeyAndEnvelope) is used by both verifySubtreeClean and the main BFS in rotateReadFromNode — no duplicated resolve+unseal logic"
    requirement: "SC#2"
    verification:
      - kind: other
        ref: "git diff packages/sdk-core/src/rotation/engine.ts — four call sites in rotateReadFromNode (enqueueConcurrentlyAddedChildren, dirty-resume seeding, root children enqueue, grandchildren enqueue) refactored to call resolveChildKeyAndEnvelope; full rotation/engine (44 tests) and folder suites green"
        status: pass
    human_judgment: false

# Metrics
duration: 20min
completed: 2026-07-07
status: complete
---

# Phase 70 Plan 05: Recursive verifySubtreeClean with Key-Bearing Frontier Summary

**verifySubtreeClean now walks the full subtree at any depth (not just root's immediate children), treats a missing root record as dirty, and returns key-bearing frontier items via a shared key-chain-walk helper reused across the main BFS**

## Performance

- **Duration:** 20 min
- **Started:** 2026-07-07T22:39:00Z
- **Completed:** 2026-07-07T22:59:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- `verifySubtreeClean` recurses the FULL subtree via a new `collectDirtyFrontier` helper: it descends into every CLEAN folder edge (parent-mirror generation matches the child's published generation) to find dirty edges at any depth, and stops recursing below a dirty edge (the derived key there is provably stale and cannot unseal the child's current body)
- A missing root IPNS record now returns `{ isDirty: true, frontier: [] }` instead of the old `{ isDirty: false, frontier: [] }` — the existing downstream caller already re-resolves root and throws a descriptive error on that path
- The frontier item shape changed to `DirtyFrontierItem { ipnsName, nodeId, parentIpnsName, nodeReadKey, childPubKind, enqueuedGeneration }` so a dirty node discovered at any depth carries an engine-derived key sufficient to seed a BFS directly (RESEARCH.md Pitfall 3) — consumption of this richer shape by `rotateReadFromNode`'s dirty-resume seeding block is deferred to plan 70-06 per this plan's own scope
- Extracted two shared module-level helpers — `resolveAndFetchNode` (resolve IPNS name → fetch → parse envelope) and `resolveChildKeyAndEnvelope` (envelope + `unsealChildReadKey` derivation) — and refactored all four existing duplicate resolve+unseal call sites inside `rotateReadFromNode`'s main BFS to use them, eliminating independently-maintained copies of the key-chain-walk logic
- Corrected the stale `verifySubtreeClean` docstring that claimed fresh-record resume was blocked on an unwired Phase-68 durable client floor

## Task Commits

Each task was committed atomically (TDD RED/GREEN):

1. **Task 1 (RED): multi-level verifySubtreeClean fixture + dirty-at-depth + missing-root cases** - `704b64429` (test)
2. **Task 2 (GREEN): recursive verifySubtreeClean + shared traversal helper + docstring fix** - `2da4357d4` (feat)

## Files Created/Modified
- `packages/sdk-core/src/rotation/engine.ts` - `verifySubtreeClean` rewritten as a recursive full-subtree walk; new `DirtyFrontierItem` type; new `resolveAndFetchNode`/`resolveChildKeyAndEnvelope` shared helpers; new `collectDirtyFrontier` recursive backing function; four existing BFS call sites (`enqueueConcurrentlyAddedChildren`, dirty-resume seeding, root's-children enqueue, grandchildren enqueue) refactored to the shared helper; docstring corrected
- `packages/sdk-core/src/__tests__/rotation/engine.test.ts` - Added a new `verifySubtreeClean — full-subtree recursion (Plan 70-05 SC#2)` describe block with 3 tests (dirty-at-depth-2, missing-root-is-dirty, clean-multi-level); adjusted two pre-existing depth-1 fixtures (Test 1 in the 64-07 `verifySubtreeClean` describe, and Test 4 in the 64-07 `resume guard` describe) to mark their clean child's published kind as `'file'`, preventing infinite recursion against their static single-value `unsealNode` mocks

## TDD Gate Compliance

RED gate: `704b64429` (`test(70-05): add RED multi-level verifySubtreeClean fixtures for SC#2`) — confirmed failing exactly on the 2 new depth-2/missing-root assertions before Task 2 (`expected false to be true` on both `isDirty` checks), with all other 349 tests in the suite (including the pre-existing depth-1 `verifySubtreeClean` tests, already adjusted for the upcoming recursion) passing.

GREEN gate: `2da4357d4` — all 44 `rotation/engine.test.ts` tests pass, including the new depth-2, missing-root, and clean-multi-level cases.

## Decisions Made
- Followed RESEARCH.md Pitfall 3's recommended frontier item shape and shared-helper extraction verbatim; no deviation from the documented design
- Recursion below a dirty edge was deliberately NOT attempted (see key-decisions above) — this is a direct consequence of the crypto constraint described in RESEARCH.md Pitfall 4 (a key genuinely lost to an interrupted prior run has no client-side recovery path), not an oversight or a deferred TODO
- Left `rotateReadFromNode`'s dirty-resume seeding block's WIRING (which items become `parentTracking` entries, how `pendingChildCount` is computed) untouched beyond the mechanical resolve+unseal dedup — the plan's own objective text scopes consumption of the new frontier shape to plan 70-06 ("so plan 70-06's BFS can seed the queue directly"), and the existing consumer code compiles and behaves identically against the new (structurally superset) return type

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Adjusted two pre-existing test fixtures to prevent infinite recursion under the new recursive implementation**
- **Found during:** Task 1 (RED) — running the RED test file to confirm expected failures
- **Issue:** Two pre-existing depth-1 `verifySubtreeClean`/`rotateReadFromNode` test fixtures had a CLEAN child edge whose published envelope defaulted to `kind: 'folder'` (via `makePublishedNode`'s default parameter), combined with a static `mockFns.unsealNode.mockResolvedValue(rootNode)` that returns the SAME node object for every call regardless of arguments. Once `verifySubtreeClean` recurses into clean folder edges, these fixtures would cause the recursive walk to call `unsealNode` again on the "child," receive the same root node back (with its own self-referencing child entry), and loop forever — hanging the test run.
- **Fix:** Explicitly set the child's published `kind` to `'file'` in both fixtures' `fetchFromIpfs` mock, so the recursion guard (`if (childPub.kind === 'folder')`) does not attempt to descend past them. No assertions changed.
- **Files modified:** packages/sdk-core/src/__tests__/rotation/engine.test.ts
- **Verification:** Full `rotation/engine` suite (44 tests) passes with no hangs/timeouts
- **Committed in:** 704b64429 (Task 1 RED commit)

---

**Total deviations:** 1 auto-fixed (1 bug — pre-existing test fixture incompatible with new recursion behavior)
**Impact on plan:** Necessary, minimal, test-only fix required by the recursion behavior itself. No scope creep, no assertion changes, no production code touched by this fix.

## Issues Encountered

None beyond the fixture-hang issue documented above (caught and fixed during RED verification, before it could hang CI). `pnpm --filter @cipherbox/sdk-core exec tsc --noEmit` reports exactly 50 pre-existing errors confined to `src/__tests__/share/grant.test.ts` (38) and `src/__tests__/cas.test.ts` (12) — the documented pre-existing baseline — both before and after this plan's commits. Zero new errors introduced.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

`verifySubtreeClean` now produces a correct, depth-agnostic dirty frontier with engine-derived keys at every dirty node, closing SC#2's "shallow verify / missing-root-as-clean" gap identified in RESEARCH.md's threat register (T-70-08). Plan 70-06 (fresh-record resume) can now consume `DirtyFrontierItem`'s richer shape (`parentIpnsName`, `nodeReadKey`, `childPubKind`, `enqueuedGeneration`) to seed the BFS queue directly per dirty node at any depth, and to restructure the entry gate per RESEARCH.md Open Question 1 (probing root-unseal viability regardless of `completedNodeIds.size`) without needing to change `verifySubtreeClean` again.

---
*Phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl*
*Completed: 2026-07-07*

## Self-Check: PASSED

Both modified files (`packages/sdk-core/src/rotation/engine.ts`, `packages/sdk-core/src/__tests__/rotation/engine.test.ts`) found on disk; both task commits (704b64429, 2da4357d4) verified present in git log.
