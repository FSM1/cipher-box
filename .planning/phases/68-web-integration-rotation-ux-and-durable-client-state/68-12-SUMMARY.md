---
phase: 68-web-integration-rotation-ux-and-durable-client-state
plan: 12
subsystem: sdk-rotation
tags: [rotation, ipns, folder-tree, sdk-core, sdk, vitest, gap-closure]

requires:
  - phase: 68-web-integration-rotation-ux-and-durable-client-state
    provides: "68-11 live-wired ROT-07 fail-closed anti-rollback gate (reconcileFolderSequence + enforceResolved); pre-existing performScopeExitRotation/rotateReadFromNode wiring from 68-05/68-08"
provides:
  - "RotateReadResult type: { readKey, generation, sequenceNumber } surfaced from rotateReadFromNode's root rotation"
  - "performScopeExitRotation refreshes the folderTree entry for the rotated root after a covered mutation"
  - "Same-session mutation on a just-scope-exit-rotated folder self-heals without a page reload"
affects: [sdk-core-rotation-engine, sdk-client, rotation-ux, rot-07]

tech-stack:
  added: []
  patterns:
    - "Additive return-type widening (void -> T | undefined) on an internal engine primitive, verified backward-compatible for all existing await-and-ignore callers via full-repo grep + typecheck diff"
    - "Terminal-owner zeroization deferred to post-flight (after the async operation that produced the buffer has fully returned), not mid-flight, to avoid zeroing a buffer still in use by a caller-supplied reference"

key-files:
  created: []
  modified:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/rotation/index.ts
    - packages/sdk-core/src/index.ts
    - packages/sdk-core/src/__tests__/rotation/engine.test.ts
    - packages/sdk/src/client.ts
    - packages/sdk/src/__tests__/client-rotation.test.ts

key-decisions:
  - "rotateReadFromNode's return is keyed off rootResult.skipped (not job-record status): the resume/dirty-resume fall-through path also returns undefined, since no FRESH root key was minted that run"
  - "Updated one pre-existing engine.test.ts assertion (resolves.toBeUndefined -> toBeDefined) that encoded the old void-return contract; its real intent (fresh run completes without invoking verifySubtreeClean) is unchanged and still asserted"
  - "folderTree refresh zeroes the OLD folderKey only AFTER the Map.set() swap, and only because rotateReadFromNode has already fully returned by that point -- never zeroes rotationResult.readKey (owned via defensive copy) or the caller-supplied rootReadKey mid-flight"

patterns-established:
  - "An internal rotation primitive's return-type change is proven backward-compatible via three checks together: full-repo grep for all call sites, tsc -b --force error-count diff (before/after), and updating any pre-existing test whose assertion encoded the OLD contract"

requirements-completed: [ROT-07]

coverage:
  - id: D1
    description: "rotateReadFromNode returns { readKey, generation, sequenceNumber } from the root's rotateOne result on a fresh rotation, and undefined on the resume/skip path (readKey not zeroed by the engine -- caller becomes terminal owner)"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#rotateReadFromNode — root-first BFS ordering (§4.2) > returns the root RotateReadResult (readKey/generation/sequenceNumber) on a fresh rotation (Gap 2)"
        status: pass
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#rotateReadFromNode — root-first BFS ordering (§4.2) > returns undefined on the clean resume/skip path (root already committed in a prior run, Gap 2)"
        status: pass
    human_judgment: false
  - id: D2
    description: "performScopeExitRotation captures rotateReadFromNode's return and refreshes the folderTree entry (folderKey/sequenceNumber/nodeGeneration) for the rotated root when -- and only when -- a rotation actually occurred"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/client-rotation.test.ts#CipherBoxClient — folderTree refresh after scope-exit rotation (Gap 2) > refreshes the folderTree entry with the rotated readKey/generation/sequenceNumber after a covered mutation"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/client-rotation.test.ts#CipherBoxClient — folderTree refresh after scope-exit rotation (Gap 2) > leaves folderTree unchanged when the mutation is uncovered (rotateReadFromNode not invoked)"
        status: pass
    human_judgment: false
  - id: D3
    description: "A second same-session mutation on a folder that was just scope-exit-rotated succeeds without a page reload -- it does not enter the unrecoverable ReconcileStaleError -> bounded-retry -> terminal-toast loop"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/client-rotation.test.ts#CipherBoxClient — folderTree refresh after scope-exit rotation (Gap 2) > a second same-folder mutation after a covered rotation does NOT throw ReconcileStaleError (self-heals without a page reload)"
        status: pass
    human_judgment: false

duration: 4min
completed: 2026-07-01
status: complete
---

# Phase 68 Plan 12: folderTree Refresh After Scope-Exit Rotation (VERIFICATION Gap 2 Closure) Summary

**`rotateReadFromNode` now surfaces the root's post-rotation `{readKey, generation, sequenceNumber}` instead of discarding it behind a `void` return, and `performScopeExitRotation` writes that result back into `folderTree` so a same-session retry on a just-rotated folder self-heals instead of permanently deferring until a page reload.**

## Performance

- **Duration:** 4 min
- **Started:** 2026-07-01T21:58:16+02:00
- **Completed:** 2026-07-01T22:02:11+02:00
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- Added an exported `RotateReadResult` type (`{ readKey: Uint8Array; generation: number; sequenceNumber: bigint }`) to `packages/sdk-core/src/rotation/engine.ts`, re-exported via the rotation barrel and the sdk-core package index.
- `rotateReadFromNode`'s signature changed from `Promise<void>` to `Promise<RotateReadResult | undefined>`: returns the root's minted `readKeyPrime`/`newGeneration`/`newSequenceNumber` from the root's own `rotateOne` call on a fresh (non-skip) rotation, and `undefined` on the resume/skip path (`rootResult.skipped`) -- covering both the clean-resume early return and the dirty-resume fall-through, since neither mints a FRESH root key this run.
- `performScopeExitRotation` (`packages/sdk/src/client.ts`) now captures this return inside its `deps.rotate` closure and, after `maybeRotateOnScopeExit` resolves, refreshes the `folderTree` entry for the rotated root's `ipnsName` with the new `folderKey`/`sequenceNumber`/`nodeGeneration` -- but only when a rotation actually produced a fresh result (no spurious write on an uncovered mutation or a resume/skip).
- Closes VERIFICATION Gap 2: a second same-session mutation on a folder that was just scope-exit-rotated now reconciles against the correct (rotated) sequence number instead of throwing an unrecoverable `ReconcileStaleError` that only a full page reload could clear.

## Task Commits

Each task followed the RED -> GREEN TDD cycle:

1. **Task 1 (RED): failing test for rotateReadFromNode's RotateReadResult return** - `36f82dc86` (test)
2. **Task 1 (GREEN): rotateReadFromNode returns root RotateReadResult** - `c5457b3bf` (feat)
3. **Task 2 (RED): failing test for folderTree refresh after scope-exit rotation** - `88d6c7a4f` (test)
4. **Task 2 (GREEN): refresh folderTree after a successful scope-exit rotation** - `dc21fe356` (feat)

_TDD gate sequence verified: both tasks show `test(68-12)` before `feat(68-12)` in git log. No REFACTOR commit was needed for either task -- the implementations required no cleanup pass._

RED confirmation for Task 1: only the new "returns the root RotateReadResult... on a fresh rotation" assertion failed against pre-implementation `engine.ts` (`expected undefined to be defined`); the companion "returns undefined on the skip path" test necessarily passed even pre-implementation since `void === undefined`, which is expected and does not weaken the RED proof (the fresh-path assertion is the one that exercises the actual code change).

RED confirmation for Task 2: both new assertions failed against pre-implementation `client.ts` -- the folderTree-refresh assertion (`state?.folderKey` mismatched the rotated key) and the self-heal assertion (threw `ReconcileStaleError` exactly as VERIFICATION Gap 2 describes). The "leaves folderTree unchanged when uncovered" case passed pre-implementation (no behavior change needed there), consistent with the plan's must-have that uncovered mutations get zero spurious writes both before and after this fix.

## Files Created/Modified

- `packages/sdk-core/src/rotation/engine.ts` - Added `RotateReadResult` type; `rotateReadFromNode` returns it on a fresh rotation, `undefined` on resume/skip
- `packages/sdk-core/src/rotation/index.ts` - Re-exports `RotateReadResult` from the rotation barrel
- `packages/sdk-core/src/index.ts` - Re-exports `RotateReadResult` from the sdk-core package index
- `packages/sdk-core/src/__tests__/rotation/engine.test.ts` - Two new cases (fresh-path return shape via a `crypto.getRandomValues` spy; skip-path `undefined`); updated one pre-existing assertion that encoded the old void-return contract
- `packages/sdk/src/client.ts` - `performScopeExitRotation` captures `rotateReadFromNode`'s return and refreshes `folderTree` for the rotated root when a rotation occurred
- `packages/sdk/src/__tests__/client-rotation.test.ts` - New describe block "folderTree refresh after scope-exit rotation (Gap 2)" with 3 cases: refresh-on-covered-mutation, self-heal-on-second-mutation, unchanged-when-uncovered

## Decisions Made

- `rotateReadFromNode`'s return is keyed off `rootResult.skipped`, checked once at the very end of the function (after the terminal `jobRecord.status = 'complete'` persist), rather than duplicating the check at every early-return site. Both the clean-resume early return and the dirty-resume fall-through path correctly return `undefined` because neither mints a FRESH root key in that run.
- The engine does not zero the returned `readKey` (rootResult.childReadKey) -- confirmed the existing success-path never zeroed it either; the caller (`performScopeExitRotation`) is now the documented terminal owner (D-09).
- `performScopeExitRotation`'s folderTree refresh zeroes the OLD `folderKey` only AFTER the `Map.set()` swap and only because `rotateReadFromNode` has already fully returned by that point in the flow -- this avoids the exact failure class documented in project memory (a callee zeroing a reused/caller-owned buffer mid-flight, which previously broke 48/89 sdk-e2e tests). `rotationResult.readKey` itself is never zeroed (it's copied into the new folderTree entry via `new Uint8Array(...)`, matching `registerFolder`/`loadFolder`'s defensive-copy discipline).
- Updated one pre-existing `engine.test.ts` assertion (`'does NOT invoke verifySubtreeClean on a fresh run'`) from `.resolves.toBeUndefined()` to `.resolves.toBeDefined()`. This assertion's actual purpose (proving the fresh run completes without a Phase-64 `verifySubtreeClean` throw) is preserved; only its incidental encoding of the OLD void-return contract changed, which is a direct and necessary consequence of this plan's additive signature widening -- not scope creep.

## Deviations from Plan

None - plan executed exactly as written. Both tasks' `<action>` and `<verify>` blocks were followed as specified. The one pre-existing test assertion update (`resolves.toBeUndefined` -> `toBeDefined` in `engine.test.ts`) was anticipated by the plan's own acceptance criteria ("Existing callers that await rotateReadFromNode(...) and ignore the result continue to compile and behave identically") and is documented above as a Decision rather than a Rule 1-4 auto-fix, since it is a direct, necessary consequence of the signature change this plan explicitly makes -- not an unplanned bug discovery.

## Issues Encountered

None. Both `pnpm --filter @cipherbox/sdk-core exec tsc -b --force` (50 errors, all pre-existing in quarantined `cas.test.ts`/`grant.test.ts` -- confirmed identical via a `git stash`/re-run diff against the pre-change baseline) and `pnpm --filter @cipherbox/sdk exec tsc -b --force` (69 errors, confirmed byte-identical pre/post via the same stash-diff technique, all in quarantined Node-v3-migration-debt test files per 68-11's prior finding) show zero NEW errors introduced by this plan's changes.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- VERIFICATION Gap 2 ("should-fix, non-blocking") is closed: `performScopeExitRotation` now refreshes `folderTree` with the rotated key/generation/sequence, so the "folderTree reconcile-before-rotate" invariant holds as a durable, self-healing property (a same-session retry succeeds) rather than a one-shot pre-check that permanently strands the session.
- Combined with 68-11's closure of Gap 1 (the fail-closed anti-rollback gate is now reachable from live resolve paths), both of `68-VERIFICATION.md`'s flagged gaps are now addressed. ROT-07 traceability should be re-verified end-to-end via a targeted re-verification pass or `/gsd-verify-work` before the requirement is marked "Complete" in `REQUIREMENTS.md`.
- No new package-manager installs were introduced (matches the plan's threat-model note); no package-legitimacy checkpoint was needed.
- The sdk-e2e suite (`tests/sdk-e2e/src/suites/read-chain-navigation.test.ts`, `rotation-crash-safety.test.ts`) calls `rotateReadFromNode` and ignores its return in all 5 call sites -- confirmed via full-repo grep that this remains valid (additive return, `await`-and-ignore still compiles and behaves identically). Per project doctrine this suite needs a live stack (docker + `api dev`, redis 6380) and was not re-run in this executor sandbox; recommend a local sdk-e2e pass before merge per the plan's own `<verification>` block.

---

*Phase: 68-web-integration-rotation-ux-and-durable-client-state*
*Completed: 2026-07-01*

## Self-Check: PASSED

All 6 modified files verified present on disk with the expected changes; all 4 task commits (`36f82dc86`, `c5457b3bf`, `88d6c7a4f`, `dc21fe356`) verified present in `git log --oneline`.
