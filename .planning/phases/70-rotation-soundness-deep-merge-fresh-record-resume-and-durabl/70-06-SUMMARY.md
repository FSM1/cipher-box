---
phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl
plan: 06
subsystem: sdk-core
tags: [rotation, crash-recovery, double-rotation, grant-remint, zeroization, elevation-of-privilege]

# Dependency graph
requires:
  - phase: 70-05
    provides: verifySubtreeClean's recursive full-subtree walk with key-bearing DirtyFrontierItem frontier shape
provides:
  - rotateReadFromNode's entry gate probes root-unseal viability before deciding fresh rotateOne(root) vs dirty-tail recovery, regardless of completedNodeIds.size
  - RootKeyStaleError — a distinct, named error for the genuinely-unrecoverable stale-root-key crash window, re-exported through both barrels
  - Safe double-rotation (design §4.5) replaces the old ROT-06 no-double-bump convergence guard — every queued node is rotated via the normal rotateOne call, never silently skipped
  - grantCallbacks/innerGrants threaded through RotationParams into every rotateOne call site so reMintGrantsRootedAt is reachable from the real (non-test) walk
  - Fail-closed pendingChildCount accounting on a missing frontier/child IPNS record — a parent can still converge and batch-republish even when one child is unresolvable
  - Dirty-resume-republish path returns a truthy RotateReadResult with a fresh-copy readKey, never an alias of the caller-owned rootReadKey
affects: [70-07, 70-08, client.ts top-down re-navigation fallback]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Read-only unseal PROBE before any mutating rotation step — resolve+unseal the current published root with the caller-supplied key to distinguish 'stale key' (throw RootKeyStaleError) from 'reachable, proceed' before committing to a fresh rotateOne(root)"
    - "Shared decrementPendingAndMaybeRepublish(parentState, key) helper collapses three previously-duplicated pendingChildCount decrement + batched-republish-when-zero blocks into one, and is reused for the NEW fail-closed missing-record accounting path"
    - "A clean edge's engine-derived key is zeroed by its own deriving function (collectDirtyFrontier) once fully processed; a dirty edge's key is left untouched since it survives into the returned frontier and is consumed by the BFS caller"

key-files:
  created: []
  modified:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/rotation/index.ts
    - packages/sdk-core/src/index.ts
    - packages/sdk-core/src/__tests__/rotation/engine.test.ts

key-decisions:
  - "RootKeyStaleError is thrown ONLY when the root record EXISTS but unseal fails with the supplied rootReadKey — a MISSING root record is a distinct scenario (data inconsistency), left to rotateOne's own 'not found in IPNS' throw / verifySubtreeClean's isDirty:true handling, never conflated with the stale-key case"
  - "The pre-rotation verifySubtreeClean call runs BEFORE rotateOne(root) so it always observes root's children mirror as-of entry (rotateOne(root) never mutates the children array, only re-seals root's own body) — this lets the SAME precomputed frontier be reused in both the skipped and non-skipped branches without a second verifySubtreeClean call"
  - "The ROT-06 no-double-bump convergence guard was REMOVED entirely from the BFS dequeue loop (not merely relaxed) — design §4.5 states an extra rotation only strengthens revocation; rotateOne's own completedNodeIds idempotency check already makes a genuinely-already-handled-this-session node a cheap no-op, so no separate skip-guard is needed"
  - "grantCallbacks/innerGrants are threaded as a SINGLE flat pair applied identically to every node in the walk (root and every BFS item) rather than per-node granularity — matches RESEARCH's explicit scope note that Phase 66 owns live per-node grant querying; this phase only needed the plumbing to exist and be reachable"
  - "Fail-closed missing-record accounting decrements pendingChildCount (explicit accounting) rather than throwing and aborting the whole walk — a missing record for ONE child must not prevent the parent from converging for every OTHER child that DOES resolve"
  - "Task 2 (entry-gate restructure) and Task 3 (grant threading) were implemented as a single interleaved edit to rotateReadFromNode and committed as one feat commit — the two concerns touch the exact same function signature and call sites, and splitting them post-hoc into separate commits would have required an error-prone partial revert with no corresponding benefit"

patterns-established:
  - "rotateReadFromNode's entry gate: probe → verifySubtreeClean (unconditional) → rotateOne(root) → branch on rootResult.skipped only to decide WHICH frontier-seeding path runs, not whether dirty-tail recovery runs at all"

requirements-completed: ["SC#3", "SC#4", "SC#6"]

coverage:
  - id: D1
    description: "rotateReadFromNode's entry gate probes root-unseal viability and runs verifySubtreeClean-driven dirty-tail recovery on a fresh record (empty completedNodeIds), converging via safe double-rotation"
    requirement: "SC#3"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#rotateReadFromNode — fresh-record resume via safe double-rotation (Plan 70-06 SC#3, supersedes 64-07 no-double-bump guard) > Test 1 (Plan 70-06): fresh job, child already at baseline+1 — safe double-rotation recovers it"
        status: pass
    human_judgment: false
  - id: D2
    description: "A stale rootReadKey (root already rotated by a lost prior run) throws a distinct RootKeyStaleError instead of a generic AEAD/unseal error"
    requirement: "SC#3"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#rotateReadFromNode — fresh-record resume via safe double-rotation (Plan 70-06 SC#3, supersedes 64-07 no-double-bump guard) > Test 2 (Plan 70-06): stale rootReadKey throws RootKeyStaleError, not a generic AEAD/unseal error"
        status: pass
    human_judgment: false
  - id: D3
    description: "grantCallbacks/innerGrants supplied on RotationParams reach queryGrantsFn via the public rotateReadFromNode walk (reMintGrantsRootedAt reachable in production, not only via direct rotateOne injection)"
    requirement: "SC#4"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#rotateReadFromNode — fresh-record resume via safe double-rotation (Plan 70-06 SC#3, supersedes 64-07 no-double-bump guard) > Test 3 (Plan 70-06 SC#4): grantCallbacks/innerGrants on RotationParams reach queryGrantsFn via the public rotateReadFromNode walk"
        status: pass
    human_judgment: false
  - id: D4
    description: "A missing child IPNS record on the frontier is fail-closed accounted (explicit pendingChildCount decrement) rather than a silent continue that desyncs the counter and stalls the parent's batched D-09 republish forever"
    requirement: "SC#3"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#rotateReadFromNode — fresh-record resume via safe double-rotation (Plan 70-06 SC#3, supersedes 64-07 no-double-bump guard) > Test 4 (Plan 70-06 / T-70-12): a missing child IPNS record is fail-closed accounted"
        status: pass
    human_judgment: false
  - id: D5
    description: "The dirty-resume-republish path returns a truthy RotateReadResult whose readKey is a fresh Uint8Array copy, never the same object reference as the caller-supplied rootReadKey"
    requirement: "SC#6"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#rotateReadFromNode — fresh-record resume via safe double-rotation (Plan 70-06 SC#3, supersedes 64-07 no-double-bump guard) > Test 5 (Plan 70-06 SC#6 / T-70-10): dirty-resume-republish returns a FRESH COPY readKey"
        status: pass
    human_judgment: false
  - id: D6
    description: "RootKeyStaleError is exported from engine.ts and re-exported via rotation/index.ts and sdk-core index.ts along the same barrel path as rotateReadFromNode; engine.ts itself stays out of any index.ts barrel"
    requirement: "SC#3"
    verification:
      - kind: other
        ref: "pnpm --filter @cipherbox/sdk-core build — dist/index.mjs/dist/index.js both contain the RootKeyStaleError class and its named export (grep-verified)"
        status: pass
    human_judgment: false

# Metrics
duration: 55min
completed: 2026-07-07
status: complete
---

# Phase 70 Plan 06: Fresh-Record Resume, RootKeyStaleError, Grant Threading, and Fresh-Copy Dirty-Resume Summary

**rotateReadFromNode's entry gate now probes root-unseal viability before choosing fresh-rotation vs dirty-tail recovery, throws a distinct RootKeyStaleError for the genuinely-unrecoverable stale-key window, converges crash-interrupted subtrees via safe double-rotation (no more no-double-bump guard), threads grantCallbacks/innerGrants into the real walk, and returns a terminal-owner-safe fresh-copy readKey on the dirty-resume path**

## Performance

- **Duration:** 55 min
- **Started:** 2026-07-07T22:20:00Z
- **Completed:** 2026-07-07T23:15:00Z
- **Tasks:** 3 (1 RED, 2 GREEN — implemented as one interleaved commit, see Decisions)
- **Files modified:** 4

## Accomplishments
- Restructured `rotateReadFromNode`'s entry gate: a read-only unseal PROBE against the currently-published root record runs first (using the caller-supplied `rootReadKey`), throwing the new `RootKeyStaleError` if the key cannot unseal an EXISTING root — a genuinely-unrecoverable window since the durable floor stores generation/sequence numbers only, never key material
- `verifySubtreeClean`-driven dirty-tail detection now runs UNCONDITIONALLY (no longer gated on `completedNodeIds.size`), consuming 70-05's key-bearing `DirtyFrontierItem` frontier to seed the BFS queue directly — even for a genuinely fresh job record whose root was already rotated by a lost prior run
- Removed the ROT-06 no-double-bump convergence guard entirely from the BFS dequeue loop; every queued node (fresh, dirty-tail, or previously-orphaned) is rotated via the normal `rotateOne` call — design §4.5's safe double-rotation (an extra rotation only strengthens revocation)
- `grantCallbacks`/`innerGrants` added to `RotationParams` and threaded to every `rotateOne` call site (root's initial call and every BFS-loop item), closing the T-70-09 elevation-of-privilege gap where `reMintGrantsRootedAt` was only reachable via direct unit-test injection
- Fail-closed accounting: a missing child IPNS/envelope record at any of the three enqueue sites (root children enqueue, dirty-resume frontier seeding, grandchildren enqueue) now explicitly decrements `pendingChildCount` via a new shared `decrementPendingAndMaybeRepublish` helper instead of a silent `continue`, so the parent's batched D-09 republish can still fire for every OTHER child that resolves
- The dirty-resume-republish path returns a truthy `RotateReadResult` whose `readKey` is `new Uint8Array(rootReadKey)` — a fresh copy, never the caller-owned buffer — closing the T-70-10 self-inflicted-DoS gap where a caller zeroing the returned key could have corrupted its own live `rootReadKey` reference
- `collectDirtyFrontier` now zeroes a CLEAN edge's derived key once fully processed (D-09 terminal-owner hygiene for the read-only verify walk); a DIRTY edge's key is deliberately left untouched since it survives into the frontier item returned to the caller

## Task Commits

1. **Task 1 (RED): fresh-resume, RootKeyStaleError, grant-reachability, fail-closed accounting, fresh-copy assertions** - `0b6a5ee2c` (test)
2. **Task 2+3 (GREEN): entry-gate restructure + RootKeyStaleError + safe double-rotation + fail-closed accounting + fresh-copy result + grantCallbacks/innerGrants threading** - `09ddfa0cf` (feat)

## Files Created/Modified
- `packages/sdk-core/src/rotation/engine.ts` - New `RootKeyStaleError` class; `RotationParams` gains `innerGrants`/`grantCallbacks`; `rotateReadFromNode`'s entry gate restructured (probe → unconditional verifySubtreeClean → rotateOne(root) with grant threading); new `decrementPendingAndMaybeRepublish` and `enqueueDirtyFrontierItem` helpers; three fail-closed accounting sites; convergence guard removed from the BFS loop; terminal return distinguishes clean-resume (`undefined`) from dirty-resume-republish (fresh-copy `RotateReadResult`); `collectDirtyFrontier` zeroes clean-edge keys
- `packages/sdk-core/src/rotation/index.ts` - Re-exports `RootKeyStaleError`, `GrantRemintCallbacks`, `DirtyFrontierItem`
- `packages/sdk-core/src/index.ts` - Re-exports `RootKeyStaleError`, `GrantRemintCallbacks`, `DirtyFrontierItem` from the rotation barrel
- `packages/sdk-core/src/__tests__/rotation/engine.test.ts` - 5 new RED-then-GREEN tests in a new describe block (`rotateReadFromNode — fresh-record resume via safe double-rotation`); the old "no-double-bump convergence guard" test rewritten to assert the OPPOSITE (double-rotation now recovers the child); two pre-existing dirty-resume fixtures adjusted (static `unsealNode` mocks that returned the wrong node object for the child, now id-dispatched) since the child is now genuinely re-entered via `rotateOne` instead of convergence-skipped

## TDD Gate Compliance

RED gate: `0b6a5ee2c` (`test(70-06): add RED cases for fresh-record resume, RootKeyStaleError, grant reachability, fail-closed accounting, and fresh-copy dirty-resume`) — verified failing by temporarily reverting `engine.ts`/`rotation/index.ts`/`index.ts` via `git checkout -- <files>` (not `git stash`, per the destructive-git prohibition) and re-running the suite: exactly the 5 new Task-1 assertions failed (350/355 passed), confirming the RED tests genuinely discriminate old vs new behavior. The implementation was then restored via `git apply` of the saved diff.

GREEN gate: `09ddfa0cf` — full `rotation/engine` suite (355 tests across 32 files) green; targeted `tsc --noEmit` confirms exactly the documented 50-error pre-existing baseline (grant.test.ts 38 + cas.test.ts 12), zero new errors; `pnpm --filter @cipherbox/sdk-core build` succeeds and the built `dist/index.js`/`dist/index.mjs` both contain `RootKeyStaleError` as a named export.

## Decisions Made

See frontmatter `key-decisions` for the full list. Highlights:
- The convergence guard was removed OUTRIGHT (not relaxed/conditionally bypassed), matching the plan's explicit prohibition against "a no-double-bump guard that blocks a safe second rotation on resume."
- Tasks 2 and 3 were implemented and committed together as a single `feat` commit — the entry-gate restructure and grant threading touch the exact same function signature and every `rotateOne` call site, making a clean post-hoc split not worthwhile.
- The pre-rotation `verifySubtreeClean` call is computed ONCE (before `rotateOne(root)` runs) and reused in both the skipped and non-skipped branches, avoiding a redundant second call and an extra network round-trip.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `collectDirtyFrontier` crashed on `childReadKey.fill(0)` when `unsealChildReadKey` is unconfigured**
- **Found during:** Task 2 (GREEN) — full suite run after adding the D-09 clean-edge zeroization
- **Issue:** A pre-existing test (`verifySubtreeClean — BFS dirty-edge frontier > Test 1`) does not configure `mockFns.unsealChildReadKey`, so it resolves to `undefined`. The new terminal-owner zeroization for clean edges called `.fill(0)` on this `undefined` value, throwing `TypeError: Cannot read properties of undefined (reading 'fill')`.
- **Fix:** Added an `instanceof Uint8Array` guard before the `.fill(0)` call — a defensive no-op in production (the real `unsealChildReadKey` always returns a proper `Uint8Array` or throws) and a safety net against under-configured test mocks.
- **Files modified:** packages/sdk-core/src/rotation/engine.ts
- **Verification:** Full `rotation/engine` suite green (355/355)
- **Committed in:** `09ddfa0cf` (Task 2+3 GREEN commit)

**2. [Rule 1 - Bug] Two pre-existing dirty-resume test fixtures collided node identity once the convergence guard was removed**
- **Found during:** Task 2 (GREEN) — full suite run after removing the convergence guard
- **Issue:** `rotateReadFromNode — resume guard > Test 3` and (transitively) similar fixtures used a STATIC `mockFns.unsealNode.mockResolvedValue(rootNode)` — a single value returned for EVERY `unsealNode` call regardless of arguments. Under the OLD convergence-guard behavior, a dirty child was never actually passed through `rotateOne` (it was witness-refresh-skipped), so this static mock was never exercised for the child. With the guard removed, the child IS now genuinely re-entered via `rotateOne`, which calls `unsealNode` on the child's own published envelope — the static mock returned the ROOT's node object instead, causing the derived `nodeId` to equal `NODE_ID` (already in `completedNodeIds`), which made `rotateOne` spuriously report `skipped: true` for the child and silently break the parent's D-09 batched republish.
- **Fix:** Changed the fixture to `mockImplementation(async (published) => published.id === NODE_ID ? rootNode : childNode)`, matching the id-dispatch pattern already used by every OTHER multi-node fixture in this file.
- **Files modified:** packages/sdk-core/src/__tests__/rotation/engine.test.ts
- **Verification:** Full `rotation/engine` suite green (355/355); RED-state re-verification confirmed this fixture change is also compatible with the OLD (pre-70-06) implementation (it did not itself change RED/GREEN discrimination for any test)
- **Committed in:** `0b6a5ee2c` (Task 1 RED commit — the fixture fix was bundled into the RED test-file commit since it is a test-infrastructure change, not production code)

**3. [Rule 1 - Bug] Test 2's `.rejects.toThrow(RootKeyStaleError)` assertion was vacuously true against the OLD implementation**
- **Found during:** RED-state verification (temporarily reverted `engine.ts`, re-ran the suite)
- **Issue:** Against the reverted (pre-70-06) `engine.ts`, `RootKeyStaleError` does not exist, so the test file's import binds it to `undefined`. Vitest's `toThrow(undefined)` degrades to a vacuous "throws something" check, which passed against the OLD generic `Error('AEAD authentication failed')` — a false green that would have violated the fail-fast RED-verification rule.
- **Fix:** Rewrote the assertion to catch the error explicitly and check `.name === 'RootKeyStaleError'` and a message pattern specific to the new probe's wording, in addition to `toBeInstanceOf(RootKeyStaleError)` — re-verified RED (fails against old code) before re-applying the implementation.
- **Files modified:** packages/sdk-core/src/__tests__/rotation/engine.test.ts
- **Verification:** Confirmed genuinely RED against the reverted implementation; GREEN against the restored implementation
- **Committed in:** `0b6a5ee2c` (Task 1 RED commit)

---

**Total deviations:** 3 auto-fixed (3 bugs — all test-infrastructure/mock-fixture fixes required by the corrected production behavior itself, per the same precedent documented in 70-05's SUMMARY). No production-code deviations beyond the plan's own stated scope.
**Impact on plan:** All three fixes are necessary, minimal, and test-only or narrowly-defensive. No scope creep — no new production behavior beyond what the plan's must_haves/acceptance_criteria specify.

## Issues Encountered

None beyond the three fixture/assertion issues documented above, all caught during RED/GREEN verification before they could reach a merged state.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

`rotateReadFromNode` now converges genuinely fresh crash-resume scenarios via safe double-rotation, surfaces a distinct actionable error for the truly-unrecoverable stale-root-key window, and no longer silently orphans a dirty node behind a convergence-skip. `grantCallbacks`/`innerGrants` plumbing is reachable end-to-end from the public entrypoint (live per-node grant querying remains Phase 66's job, per RESEARCH's explicit scope boundary). Plan 70-07 can build the client-side `RootKeyStaleError` → top-down re-navigation fallback on top of this distinct error type without needing any further engine.ts changes. Plan 70-08 (sdk-e2e phase gate) should exercise a genuine mid-walk crash-then-resume scenario against the live stack to empirically confirm the double-rotation convergence path holds under real (non-mocked) crypto — this plan's unit coverage proves the WIRING and control flow, not the full cryptographic round-trip under real key derivation.

---
*Phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl*
*Completed: 2026-07-07*

## Self-Check: PASSED

All four modified/verified files found on disk (`packages/sdk-core/src/rotation/engine.ts`, `packages/sdk-core/src/rotation/index.ts`, `packages/sdk-core/src/index.ts`, `packages/sdk-core/src/__tests__/rotation/engine.test.ts`); both task commits (`0b6a5ee2c`, `09ddfa0cf`) verified present in git log.
