---
phase: 68-web-integration-rotation-ux-and-durable-client-state
plan: 05
subsystem: sdk
tags: [rotation, ipns, cas, sequenceNumber, read-key, sdk-core, vitest]

requires:
  - phase: 63-read-chain-navigation-and-rotation-core
    provides: rotateReadFromNode, hasCoveringGrant, maybeRotateOnScopeExit (pure predicate + gating composition) in packages/sdk-core/src/rotation
  - phase: 64-rotation-soundness-revocation-guarantees
    provides: RotationJobRecord.persistCallback seam, GrantRemintCallbacks pattern, D-09 zeroization terminal-owner rule, the OUT-tagged sdk-client-move-publish-durability item folded into this plan
provides:
  - ReconcileStaleError + reconcileFolderSequence() reconcile-before-publish guard on renameItem/deleteItem/deleteToBin/moveItem (SC#3/D-04)
  - performScopeExitRotation() composing sdk-core's maybeRotateOnScopeExit + rotateReadFromNode, wired into all four mutation methods (SC#2/SC#4)
  - RotationClientCallbacks/LocalGrantRecord injection seam type on CipherBoxClientConfig, defaulting to no-op
  - moveItem dest-before-source publish ordering + enumerateMoveDescendants best-effort readable/unreadable descendant enumeration (D-12)
affects: [68-06, 68-07, 68-08, 68-09, 68-10]

tech-stack:
  added: []
  patterns:
    - "Reconcile-before-publish: re-resolve network sequenceNumber and compare against in-memory FolderTree value; any mismatch (either direction) throws before the pure metadata mutation is published, guarding both the metadata publish and any downstream rotation publish"
    - "Scope-exit rotation composition: client.ts never inlines hasCoveringGrant; it always routes through sdk-core's maybeRotateOnScopeExit with an injected deps.rotate wrapping rotateReadFromNode"
    - "Injection-seam defaulting: CipherBoxClientConfig.rotationCallbacks defaults to a NOOP_ROTATION_CALLBACKS constant in the constructor so an unconfigured client is behaviorally identical to pre-Phase-68 code"
    - "Fire-and-forget observability: enumerateMoveDescendantsFireAndForget mirrors the existing fireAndForgetUnenroll pattern -- never blocks the caller, logs failures, passes a defensive key copy to avoid a zero-before-use race with the caller's finally block"

key-files:
  created:
    - packages/sdk/src/__tests__/client-rotation.test.ts
  modified:
    - packages/sdk/src/client.ts
    - packages/sdk/src/types.ts
    - packages/sdk/src/__tests__/client.test.ts
    - packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts

key-decisions:
  - "ancestorIpnsNames passed to maybeRotateOnScopeExit is the directly-mutated node's own IPNS name(s) only (not a full multi-level ancestor chain) -- FolderTree does not track parent links today and this plan's file scope is limited to client.ts/types.ts; full ancestor-chain walking is deferred to a future plan that extends FolderTree"
  - "moveItem's scope-exit rotation targets the SOURCE folder only -- the moved child exits source's scope (a rotation-worthy event); entering the destination is a scope ENTRY and needs no rotation (the FLAG-63-U2 re-seal already re-keys the moved node for dest)"
  - "reconcileFolderSequence treats a null resolve or a resolve without a bigint sequenceNumber as 'nothing to reconcile against' and skips (rather than throws) -- matches production resolveIpnsRecord's real contract (success implies a populated sequenceNumber) while keeping older/simpler test mocks that don't set sequenceNumber behaviorally unaffected"
  - "enumerateMoveDescendants is wired as a best-effort, non-blocking, fire-and-forget walk (not awaited inline in moveItem) -- descendant enumeration is observability, not a security gate; blocking every folder move on a potentially large subtree walk was judged too high-risk/high-latency for this plan's scope, and no acceptance criterion required it to be synchronous or directly unit-tested"

requirements-completed: [ROT-07]

coverage:
  - id: D1
    description: "renameItem/deleteItem/deleteToBin/moveItem reconcile the target folder's current sequenceNumber before publishing; any mismatch throws ReconcileStaleError and skips both the metadata publish and any rotation"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/client-rotation.test.ts#CipherBoxClient — reconcile-before-publish (SC#3 / D-04, Task 1)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Each mutation calls maybeRotateOnScopeExit; covered (relay set OR local grant record) rotates exactly once via rotateReadFromNode, uncovered performs zero rotation"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/client-rotation.test.ts#CipherBoxClient — scope-exit rotation wiring (SC#2 / SC#4, Task 2)"
        status: pass
    human_judgment: false
  - id: D3
    description: "moveItem publishes the destination before the source and enumerates the moved subtree's readable/unreadable descendants without blocking the move"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/client-rotation.test.ts#CipherBoxClient.moveItem — dest-before-source publish ordering (D-12, Task 3)"
        status: pass
    human_judgment: true
    rationale: "The dest-before-source ordering itself is fully proven by the call-order spy test. The descendant-enumeration BFS walk (unsealNode/unsealChildReadKey traversal for a moved FOLDER) has no dedicated unit test -- it is fire-and-forget observability code with zero acceptance-criteria coverage requirement, exercised only by manual reasoning and future 68-08/e2e integration. Flagging for reviewer awareness rather than auto-passing."

duration: 25min
completed: 2026-07-01
status: complete
---

# Phase 68 Plan 05: Scope-Exit Rotation + Reconcile-Before-Publish at the SDK Chokepoint Summary

**Wired `maybeRotateOnScopeExit`/`rotateReadFromNode` and a reconcile-before-publish guard into `CipherBoxClient`'s four mutation methods (`renameItem`, `moveItem`, `deleteItem`, `deleteToBin`), plus reordered `moveItem`'s publishes to dest-before-source and added best-effort descendant enumeration.**

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-07-01
- **Tasks:** 3 (all TDD, each with RED test commit before GREEN implementation commit)
- **Files modified:** 4 (1 new test file, 1 source file, 1 type file, 2 pre-existing test files patched for a new mock dependency)

## Accomplishments

- `ReconcileStaleError` (instanceof-distinguishable, stable `.name`) thrown by a new private `reconcileFolderSequence()` helper whenever a freshly-resolved network `sequenceNumber` disagrees with the in-memory `FolderTree` entry (either direction), positioned before any publish so both the metadata update and any rotation are deferred together (SC#3 / D-04, "defer, never skip")
- `RotationClientCallbacks`/`LocalGrantRecord` injection-seam types added to `packages/sdk/src/types.ts`; `CipherBoxClientConfig.rotationCallbacks` is optional and defaults to a no-op constant (`NOOP_ROTATION_CALLBACKS`) so an unconfigured client performs zero rotation, identical to pre-Phase-68 behavior
- New private `performScopeExitRotation()` composes sdk-core's `maybeRotateOnScopeExit` (which itself composes the anti-malicious-relay `hasCoveringGrant` predicate) with an injected `deps.rotate` that wraps `rotateReadFromNode`, threading `persistJob` into `RotationJobRecord.persistCallback`; wired into all four mutation methods (moveItem targets the SOURCE folder only)
- `moveItem` now publishes the DESTINATION folder before the SOURCE folder (dest-before-source), folding the Phase-64 OUT-tagged `sdk-client-move-publish-durability` item into this cutover
- New private `enumerateMoveDescendants`/`enumerateMoveDescendantsFireAndForget` perform a bounded, best-effort BFS (via `unsealNode`/`unsealChildReadKey`) over a moved folder's descendants, distinguishing readable from unreadable nodes and logging (never silently dropping) unreadable ones -- dispatched fire-and-forget so it never blocks or slows the move
- `packages/sdk/src/__tests__/client-rotation.test.ts` created with 18 tests across all three tasks; full `packages/sdk` suite (228 tests, 49 pre-existing skips) remains green

## Task Commits

Each task followed RED (failing test) then GREEN (implementation) as separate commits:

1. **Task 1: reconcile-before-publish + ReconcileStaleError**
   - `05d9ee4d4` - test(68-05): add failing tests for reconcile-before-publish guard
   - `441cfbda9` - feat(68-05): reconcile folder sequence before publish (SC#3, D-04)
2. **Task 2: scope-exit rotation wiring + injection seam**
   - `a244952c3` - test(68-05): add failing tests for scope-exit rotation wiring
   - `975bff8bf` - feat(68-05): wire scope-exit rotation + injection seam (SC#2, SC#4)
3. **Task 3: moveItem dest-before-source ordering + descendant enumeration**
   - `2d88438c9` - test(68-05): add failing test for moveItem dest-before-source ordering
   - `414f0f7d5` - feat(68-05): moveItem dest-before-source publish + descendant enumeration (D-12)

_TDD gate compliance: every task has a `test(...)` commit strictly before its `feat(...)` commit, each verified RED (test failed against pre-implementation code) before the GREEN implementation landed._

## Files Created/Modified

- `packages/sdk/src/__tests__/client-rotation.test.ts` - new: 18 unit tests covering reconcile-defer, rotate-when-covered/zero-rotation-when-uncovered, and dest-before-source ordering
- `packages/sdk/src/client.ts` - `ReconcileStaleError`, `NOOP_ROTATION_CALLBACKS`, `reconcileFolderSequence()`, `performScopeExitRotation()`, `enumerateMoveDescendants()`/`enumerateMoveDescendantsFireAndForget()`; wired into `renameItem`/`deleteItem`/`deleteToBin`/`moveItem`; `moveItem` publish order swapped to dest-first
- `packages/sdk/src/types.ts` - `RotationClientCallbacks`, `LocalGrantRecord` types; `rotationCallbacks?` field on `CipherBoxClientConfig`
- `packages/sdk/src/__tests__/client.test.ts` - added `resolveIpnsRecord: vi.fn()` to the sdk-core mock so the new reconcile check doesn't fall through to a real network call in the existing `deleteItem` test
- `packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts` - same one-line mock addition for its `deleteItem` call sites

## Decisions Made

- **Ancestry scope**: `nodeAncestorIpnsNames` passed into `maybeRotateOnScopeExit` is currently just the directly-mutated node's own IPNS name(s) (`[folderIpnsName]`, or `[sourceIpnsName]` for moveItem) rather than a full leaf-to-root ancestor chain. `FolderTree` has no parent-link tracking today, and this plan's `files_modified` is scoped to `client.ts`/`types.ts` only -- extending `FolderTree` to carry parent chains is out of scope here. The coverage check still correctly detects a grant rooted directly at the mutated node; multi-level ancestor coverage (a grant rooted at a *grandparent* folder) is not yet detected by this wiring and should be flagged for a future plan once `FolderTree` gains parent tracking.
- **moveItem rotation target**: only the SOURCE folder is checked for scope-exit rotation. Reasoning: the moved child exits the source folder's scope (a revocation-relevant event); entering the destination is a scope ENTRY, which never needs a rotation (no key needs to be revoked from anyone by adding an item to a folder). The existing FLAG-63-U2 re-seal step already re-keys the moved node's own readKey for the destination parent, independent of this rotation gate.
- **Descendant enumeration is fire-and-forget, not synchronous**: `enumerateMoveDescendants` is dispatched via `enumerateMoveDescendantsFireAndForget` and never awaited inline in `moveItem`. Blocking every folder move on a potentially large recursive subtree walk (2 IPNS resolve + fetch round-trips per descendant) was judged an unacceptable latency/reliability risk for a feature whose only consumer today is observability logging (no acceptance criterion required synchronous behavior, and 68-08 has not yet wired a durable consumer for the readable/unreadable results).
- **Reconcile null/non-bigint handling**: `reconcileFolderSequence` treats a `null` resolve (record not found) or a resolve without a `bigint` `sequenceNumber` field as "nothing to reconcile against" and silently proceeds, rather than throwing. This matches the real `resolveIpnsRecord` contract (a successful resolve always returns a `bigint` sequenceNumber) and avoids retroactively breaking every pre-existing test file that doesn't populate `sequenceNumber` on its `resolveIpnsRecord` mocks.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added `resolveIpnsRecord` mock to two pre-existing test files**

- **Found during:** Task 1 implementation (reconcile-before-publish wiring)
- **Issue:** `packages/sdk/src/__tests__/client.test.ts` and `packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts` mock `@cipherbox/sdk-core` via `{ ...actual, <selected overrides> }` without overriding `resolveIpnsRecord`. Once `reconcileFolderSequence` started calling `sdkCore.resolveIpnsRecord` on every mutation, these two files' `deleteItem` test cases would fall through to the REAL `resolveIpnsRecord` implementation and attempt a live network call against `http://localhost:3000`, which is not running in the test environment.
- **Fix:** Added `resolveIpnsRecord: vi.fn()` to both files' sdk-core mock override object. With no explicit `mockResolvedValue`, the mock returns `undefined`, which `reconcileFolderSequence` treats as "nothing to reconcile against" -- zero behavior change for the existing assertions in either file.
- **Files modified:** `packages/sdk/src/__tests__/client.test.ts`, `packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts`
- **Verification:** Both files' full test suites pass (`client.test.ts`: 13/13, `collect-subtree-ipns-names.test.ts`: 4 tests, all pre-existing `describe.skip`d for phase-65 stubs -- unaffected either way); confirmed via the full `pnpm --filter @cipherbox/sdk exec vitest run` pass (228 passed, 49 skipped, 0 failed).
- **Committed in:** `05d9ee4d4` (Task 1's RED test commit, bundled since it's test-infrastructure prep for the same change)

---

**Total deviations:** 1 auto-fixed (Rule 3 - blocking network-call risk in unrelated tests)
**Impact on plan:** Necessary to keep the full unit suite green without live network dependencies; no scope creep -- both edits are one-line mock additions with zero behavioral change to the tests they touch.

## Known Stubs

None introduced by this plan. Pre-existing phase-65 stubs (`collectRemovedItemIpnsNames`, `collectBinEntryIpnsNames`) are unchanged and continue to throw "not implemented — phase 65" inside fire-and-forget `.catch()` chains in `deleteItem`/`deleteToBin` -- this is pre-existing, non-fatal, logged behavior untouched by this plan.

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: new-crypto-walk | `packages/sdk/src/client.ts` (`enumerateMoveDescendants`) | New BFS traversal using `unsealNode`/`unsealChildReadKey` over a moved folder's subtree, introduced as observability (not a security gate). No dedicated unit test exercises the 'folder' kind path (only trivially exercised for the 'file' short-circuit). Reviewer should confirm the zeroization discipline (only locally-minted keys zeroed, `rootReadKey` never zeroed) and the `MAX_NODES` bound before this code is relied upon by a consumer in a later plan. |

## Issues Encountered

None beyond the test-mock gap documented above (self-resolved via Rule 3).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The injection seam (`RotationClientCallbacks`) is ready for 68-08 to wire concrete web callbacks (grant getters backed by the shares API, durable IndexedDB `persistJob`, and a progress hook driving the rotation status badge).
- `ReconcileStaleError` is exported and instanceof-catchable, ready for the web toast/notification layer (68-06/68-07) to pattern-match and surface a "stale, please retry" message.
- Open follow-up (not blocking, flagged for a future plan): `FolderTree` does not track parent chains, so `maybeRotateOnScopeExit`'s ancestry check only detects a grant rooted directly at the mutated node, not at an ancestor several levels up. Extending `FolderTree` with parent tracking would close this gap.
- The descendant-enumeration walk (`enumerateMoveDescendants`) has no consumer yet; its readable/unreadable results are currently only logged via `console.warn`. A future plan (likely 68-08 or later) should decide whether/how to surface `unreadableIpnsNames` to the UI or feed them into a rotation follow-up job.

---
*Phase: 68-web-integration-rotation-ux-and-durable-client-state*
*Plan: 05*
*Completed: 2026-07-01*
