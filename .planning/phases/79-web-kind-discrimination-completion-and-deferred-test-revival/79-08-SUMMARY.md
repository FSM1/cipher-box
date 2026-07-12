---
phase: 79-web-kind-discrimination-completion-and-deferred-test-revival
plan: 08
subsystem: ui
tags: [vitest, typescript, shared-folder, test-revival, kind-discrimination]

# Dependency graph
requires:
  - phase: 79-01
    provides: "ResolvedChild.createdAt mandatory field on the SDK-resolved listing model"
provides:
  - "Revived useSharedWriteOps moveItemHandler + batchMoveItemsHandler suites (zero skip, zero markers)"
  - "createdAt on the ResolvedChild fixtures in useSharedWriteOps.test.ts, useSyncPolling.test.ts, folder.store.test.ts"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Revived describe blocks assert against the live client.moveInSharedFolder signature (itemId = SealedChildRef.ipnsName)"

key-files:
  created: []
  modified:
    - apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts
    - apps/web/src/hooks/__tests__/useSyncPolling.test.ts
    - apps/web/src/stores/__tests__/folder.store.test.ts

key-decisions:
  - "Two revived assertions were stale vs the live signature and were corrected (not re-skipped, per the plan's fallback): (1) the vaultKeypair-absent moveItem case surfaces 'Not authenticated' — the live message — not the stale 'No keypair available'; (2) the empty-items batch case is a vacuous success that still calls clearSelection (the live handler has no early-return guard for an empty batch), so the assertion now expects clearSelection to be called once."
  - "The stale 'No keypair available' expectation was ALSO the root cause of the batch suite's 0-call failures: its assertion failed before getStateSpy.mockRestore() ran, leaking a null-vaultKeypair auth mock into the later batch tests (which then early-returned). Fixing the expected message restored the spy and the batch suite went green."
  - "folder.store.test.ts's makeChild fixture was fixed here even though it is outside the plan's files_modified: it carries the identical mandatory-createdAt compile break and was the 4th of the 4 pre-existing apps/web tsc -b errors. Folding its one-line fix in is what brings apps/web tsc -b fully green; no store-test behavior changed."

patterns-established: []

requirements-completed: []

coverage:
  - id: SC3-revive-shared-move-suites
    description: "moveItemHandler + batchMoveItemsHandler describe.skip blocks un-skipped and passing"
    verification:
      - kind: test
        ref: "pnpm --filter @cipherbox/web test -- useSharedWriteOps.test.ts (15 tests pass, 0 skip)"
        status: pass
    human_judgment: false
  - id: SC3-zero-skip-zero-markers
    description: "zero describe.skip and zero deferred TODO(phase 65) markers remain in useSharedWriteOps.test.ts"
    verification:
      - kind: other
        ref: "grep -n 'phase 63|phase 65|describe.skip|.skip(' useSharedWriteOps.test.ts returns zero"
        status: pass
    human_judgment: false
  - id: fixtures-createdAt
    description: "Both web hook test ResolvedChild fixtures (plus folder.store) carry createdAt so they typecheck"
    verification:
      - kind: other
        ref: "apps/web tsc -b reports zero errors"
        status: pass
    human_judgment: false

# Metrics
duration: 18min
completed: 2026-07-12
status: complete
---

# Phase 79 Plan 08: Revive Shared-Write Hook Suite and Repair createdAt Fixtures Summary

**Un-skipped the shared move and batch-move hook suites (now 15 passing tests, zero skip, zero markers), corrected two stale assertions to the live `client.moveInSharedFolder` signature, and added `createdAt` to the three apps/web `ResolvedChild` test fixtures — bringing apps/web `tsc -b` fully green under Plan 01's mandatory field.**

## Performance

- **Duration:** 18 min
- **Tasks:** 2 (+ 1 folded out-of-scope compile-fix)
- **Files modified:** 3

## Accomplishments

- Removed `.skip` from both `moveItemHandler` and `batchMoveItemsHandler` describe blocks; added `createdAt: 0` to the ResolvedChild fixture and removed the stale header + two inline `phase 65` annotations.
- Corrected the vaultKeypair-absent assertion to the live `'Not authenticated'` message (was `'No keypair available'`) — this also fixed the batch suite's cascading 0-call failures caused by the failing assertion leaking a null-keypair auth spy.
- Corrected the empty-items batch assertion to expect `clearSelection` once (the live handler has no early-return for an empty batch — it is a vacuous success).
- Added `createdAt` to `makeResolvedChild` (useSyncPolling.test.ts) and `makeChild` (folder.store.test.ts) fixtures.
- Result: `pnpm --filter @cipherbox/web test` for these files → 31/31 pass; `apps/web tsc -b` → zero errors.

## Task Commits

1. **Task 1: revive shared move/batch-move suites + fixture + live-signature assertion fixes** — `19679a3d8` (test)
2. **Task 2 (+ folded folder.store fixture): createdAt on ResolvedChild test fixtures** — `7bb2d34e0` (test)

_STATE.md/ROADMAP.md are updated in a batched wave-tracking commit per this worktree's convention; SUMMARY.md is committed separately._

## Files Created/Modified

- `apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts` — un-skip both blocks, createdAt fixture, two live-signature assertion corrections, markers removed
- `apps/web/src/hooks/__tests__/useSyncPolling.test.ts` — createdAt on makeResolvedChild
- `apps/web/src/stores/__tests__/folder.store.test.ts` — createdAt on makeChild (folded compile-fix)

## Decisions Made

- Fixed the two stale assertions to the live signature rather than re-skipping (per the plan's explicit fallback). RESEARCH's "assertions already match the live signature" claim held for the itemId=ipnsName assertions but not for the error-message and empty-batch cases.
- Folded folder.store.test.ts (outside files_modified) because it was the 4th mandatory-createdAt compile break and blocked a green tsc -b; the fix is a one-line fixture field, no behavior change.

## Deviations from Plan

- Corrected two assertions beyond a pure un-skip (the plan anticipated this via its "fix the mock to the live signature, do NOT re-skip" fallback).
- Modified folder.store.test.ts, which is outside the plan's declared files_modified, as a documented compile-fix to close the unowned 4th tsc error.

## Issues Encountered

- The batch suite's initial 0-call failures were a cascading side effect of the stale `'No keypair available'` assertion (spy leak), not a batch-handler defect — resolved by the message fix.

## User Setup Required

None.

## Next Phase Readiness

- SC3 fourth deferred suite revived and passing; apps/web `tsc -b` fully green.
- Note: four non-TODO `phase 63/65` references remain in out-of-scope files (`useDropUpload.ts` inline comments; `useSharedNavigation.ts` `@stub` docs) describing genuinely-deferred Node-read-chain functionality — they are not `TODO(phase 6x)` markers and were never in phase 79's marker-triage scope.

---
*Phase: 79-web-kind-discrimination-completion-and-deferred-test-revival*
*Completed: 2026-07-12*

## Self-Check: PASSED

- FOUND: apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts
- FOUND: apps/web/src/hooks/__tests__/useSyncPolling.test.ts
- FOUND: apps/web/src/stores/__tests__/folder.store.test.ts
- FOUND: .planning/phases/79-web-kind-discrimination-completion-and-deferred-test-revival/79-08-SUMMARY.md
- FOUND commit: 19679a3d8
- FOUND commit: 7bb2d34e0
