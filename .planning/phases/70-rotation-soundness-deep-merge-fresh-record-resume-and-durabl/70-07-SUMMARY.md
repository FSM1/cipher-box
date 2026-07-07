---
phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl
plan: 07
subsystem: sdk
tags: [rotation, zeroization, crash-recovery, client, folder-tree, elevation-of-privilege]

# Dependency graph
requires:
  - phase: 70-06
    provides: RootKeyStaleError (distinct, exported via sdk-core barrel) + fresh-copy dirty-resume RotateReadResult.readKey (never an alias of caller-owned rootReadKey)
provides:
  - performScopeExitRotation zeroes rotationResult.readKey as the terminal owner, after (and independent of) the folderTree defensive copy — closes the SC#6 client-side zeroization gap
  - client.ts catches RootKeyStaleError from rotateReadFromNode (typed via the sdkCore barrel) and falls back to a top-down folderTree re-navigation from the vault root instead of failing the already-published mutation
  - a documented trace (Open Question 2): revokeShare never triggers rotation at all, and rotateReadFromNode never re-seals a rotation root's own ancestor SealedChildRef mirror — an accepted residual that can block Task 2's re-nav fallback one hop earlier
affects: [70-08]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Terminal-owner zeroization gated on `if (rotationResult)` but OUTSIDE the `if (existing)` folderTree-copy block — zeroes even when no folderTree entry exists to receive a copy, since performScopeExitRotation owns the buffer either way once the engine has returned it"
    - "Typed error-instance catch (`err instanceof sdkCore.RootKeyStaleError`) inside a rotate() closure, re-throwing anything else unchanged — never a string/message match"
    - "Best-effort secondary-step recovery: the primary mutation (rename/delete/move/create) has ALREADY published successfully by the time performScopeExitRotation runs; a stale-key rotation failure is recovered or reported without unwinding the already-succeeded mutation's own effects"

key-files:
  created: []
  modified:
    - packages/sdk/src/client.ts
    - packages/sdk/src/__tests__/client-rotation.test.ts

key-decisions:
  - "The terminal-owner fill(0) for rotationResult.readKey runs unconditionally whenever rotationResult is truthy, not only inside the `if (existing)` folderTree-copy branch — a defensive superset of the plan's literal instruction so the engine-handed-over buffer is never leaked even in the (unlikely) case folderTree has no entry for rootNodeIpnsName"
  - "On RootKeyStaleError, the client does NOT retry rotateReadFromNode after a successful top-down re-navigation. Recovery only rehydrates folderTree with the CURRENT key; the deferred rotation itself is picked up naturally by whichever NEXT covered scope-exit mutation targets that folder — avoids an unbounded retry loop inside a single mutation call"
  - "The stale folderTree entry is deleted (via FolderTree.delete, which self-zeroes) BEFORE calling ensureFolderLoaded, so ensureFolderLoaded cannot short-circuit on the same stale cached copy and is forced through a genuine re-derivation"
  - "Task 3 is a trace-and-document-only task per its own acceptance criteria — no ancestor-mirror rotation code was added. The finding (pure-revoke never rotates eagerly; rotation-on-mutation never re-seals its own root's ancestor mirror) is recorded as a doc comment on performScopeExitRotation itself (the single method both Task 2's fallback and Task 3's trace concern), not only in this SUMMARY, so future readers of the rotation call sites see the residual in context"

patterns-established:
  - "performScopeExitRotation is the terminal owner of sdkCore.RotateReadResult.readKey; any future caller of rotateReadFromNode outside this method must establish its own terminal-owner contract rather than assuming the engine zeroes on its behalf"

requirements-completed: ["SC#3", "SC#6"]

coverage:
  - id: D1
    description: "performScopeExitRotation zeroes rotationResult.readKey as terminal owner after the folderTree defensive copy, without touching the folderTree copy or the caller-owned rootReadKey"
    requirement: "SC#6"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/client-rotation.test.ts#CipherBoxClient — folderTree refresh after scope-exit rotation (Gap 2) > T-70-13 / SC#6: zeroes rotationResult.readKey as terminal owner without touching the folderTree copy or the caller-owned rootReadKey (paired zeroization invariant)"
        status: pass
    human_judgment: false
  - id: D2
    description: "client.ts catches RootKeyStaleError (typed, via the sdkCore barrel) and falls back to a full top-down folderTree re-navigation from the vault root, recovering without failing the already-published mutation"
    requirement: "SC#3"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/client-rotation.test.ts#CipherBoxClient — RootKeyStaleError top-down re-navigation fallback (Plan 70-07 Task 2) > recovers via top-down re-navigation and does not fail the (already-published) mutation"
        status: pass
    human_judgment: false
  - id: D3
    description: "When top-down re-navigation also cannot recover the root, a clear, actionable error is surfaced instead of a generic AEAD/unseal failure"
    requirement: "SC#3"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/client-rotation.test.ts#CipherBoxClient — RootKeyStaleError top-down re-navigation fallback (Plan 70-07 Task 2) > surfaces a clear, actionable error (not a generic AEAD failure) when top-down re-navigation also cannot recover the root"
        status: pass
    human_judgment: false
  - id: D4
    description: "A non-RootKeyStaleError thrown by rotateReadFromNode is NOT caught by the new fallback — it propagates unchanged"
    requirement: "SC#3"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/client-rotation.test.ts#CipherBoxClient — RootKeyStaleError top-down re-navigation fallback (Plan 70-07 Task 2) > does not catch a non-RootKeyStaleError from rotateReadFromNode — propagates as-is without attempting re-navigation"
        status: pass
    human_judgment: false
  - id: D5
    description: "Open Question 2 trace: revokeShare (pure revoke) never invokes performScopeExitRotation, and rotateReadFromNode never re-seals a rotation root's own ancestor SealedChildRef mirror — documented as an accepted residual limiting Task 2's fallback one hop earlier, no scope expansion"
    requirement: "SC#3"
    verification:
      - kind: other
        ref: "packages/sdk/src/client.ts — performScopeExitRotation doc comment, 'Plan 70-07 Task 3 trace (Open Question 2)' block; confirmed by grep -rn \"performScopeExitRotation\" packages/sdk/src/client.ts (5 call sites, all rootNodeIpnsName === the directly-mutated folder) and packages/sdk-core/src/rotation/engine.ts (parentTracking.set(rootNodeIpnsName, ...) — never seeded for the root's true ancestor)"
        status: pass
    human_judgment: false

# Metrics
duration: 13min
completed: 2026-07-07
status: complete
---

# Phase 70 Plan 07: RootKeyStaleError Client Fallback, Terminal-Owner Zeroization, and Pure-Revoke Ancestor-Mirror Trace Summary

**performScopeExitRotation now zeroes the engine-handed-over readKey as terminal owner (closing the SC#6 leak), client.ts recovers from a stale root key via top-down re-navigation instead of failing an already-published mutation, and the pure-revoke ancestor-mirror staleness (Open Question 2) is traced and documented as an accepted residual**

## Performance

- **Duration:** 13 min
- **Started:** 2026-07-07T23:17:37+02:00
- **Completed:** 2026-07-07T23:30:14+02:00
- **Tasks:** 3
- **Files modified:** 2

## Accomplishments
- `performScopeExitRotation` zeroes `rotationResult.readKey` unconditionally whenever a rotation actually ran, AFTER (and independent of) the folderTree's own defensive copy — closes the SC#6 gap where the engine-returned `readKey` was leaked (never zeroed by its caller). Safe specifically because plan 70-06 guarantees `rotateReadFromNode` always hands over a FRESH copy, never an alias of `params.rootReadKey`
- `client.ts` now catches `RootKeyStaleError` (typed via the `sdkCore` barrel export, not a string match) from `rotateReadFromNode` inside `performScopeExitRotation`'s `rotate()` closure. On catch, it drops the stale `folderTree` entry (via `FolderTree.delete`, which self-zeroes) and re-navigates top-down from the vault root via `ensureFolderLoaded` to rediscover the current key through the parent chain — no cryptographic key recovery is claimed, only chain re-derivation, matching RESEARCH's Open Question 1 recommendation
- When the top-down re-navigation itself cannot recover the root (the Open Question 2 residual), a clear, actionable `Error` is thrown (with the original `RootKeyStaleError` attached via `{ cause: err }`) instead of letting a generic AEAD/unseal failure surface
- Traced and documented Open Question 2 directly on `performScopeExitRotation`'s doc comment: all five call sites (`createSubfolder`, `renameItem`, `moveItem`, `deleteItem`, `deleteToBin`) invoke the method with `rootNodeIpnsName` equal to the directly-mutated folder itself; `revokeShare` (the pure-revoke path) never calls this method at all, so rotation of a revoked root is entirely deferred to whatever later direct mutation eventually targets that folder; and even then, `rotateReadFromNode` never re-seals the rotation root's own ancestor `SealedChildRef` mirror (confirmed via `parentTracking` in `engine.ts`, which is seeded keyed by the root's OWN ipns name for tracking its children, never for its true parent) — an accepted residual, no scope expansion

## Task Commits

1. **Task 1: Zero rotationResult.readKey (terminal owner) + paired zeroization test** - `c138160f4` (feat)
2. **Task 2: Catch RootKeyStaleError -> top-down re-navigation fallback** - `7c06f9de0` (feat)
3. **Task 3: Trace + document Open Question 2 (pure-revoke ancestor-mirror staleness)** - `1e6b0978a` (docs)

## Files Created/Modified
- `packages/sdk/src/client.ts` - `performScopeExitRotation` zeroes `rotationResult.readKey` as terminal owner; its `rotate()` closure catches `RootKeyStaleError` and falls back to top-down re-navigation via `ensureFolderLoaded`, throwing a clear actionable error when that also fails; doc comment extended with the Open Question 2 trace note
- `packages/sdk/src/__tests__/client-rotation.test.ts` - extended with a paired zeroization-invariant test (owner-zeroed / folderTree-copy-unchanged / caller-rootReadKey-unchanged), a new describe block covering the RootKeyStaleError recovered/unrecoverable/non-stale-passthrough cases, and a fix to the pre-existing folderTree-refresh test (snapshot expected bytes before the call, since the mock's `readKey` reference is now zeroed in place by the code under test)

## Decisions Made

See frontmatter `key-decisions` for the full list. Highlights:
- Zeroization fires whenever `rotationResult` is truthy, not gated on `existing` being found in folderTree — a defensive superset that never leaks the engine-owned buffer regardless of folderTree state.
- No retry of `rotateReadFromNode` after a successful re-navigation recovery — the already-published mutation must not be blocked on a synchronous rotation retry; the deferred rotation is naturally retried by the next covered scope-exit mutation.
- Task 3's finding is recorded as a doc comment on `performScopeExitRotation` itself (not only in this SUMMARY), since it is directly load-bearing context for anyone reading or modifying the Task 2 fallback logic right above it.

## Deviations from Plan

None - plan executed exactly as written. The existing `client-rotation.test.ts` test "refreshes the folderTree entry with the rotated readKey/generation/sequenceNumber after a covered mutation" required a fix (snapshotting expected bytes before the call) as a direct, necessary consequence of Task 1's own zeroization change — this is documented as part of Task 1's own scope (the plan explicitly required paired assertions), not tracked as a separate Rule 1 deviation.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Plan 70-08 (sdk-e2e phase gate) can now exercise the RootKeyStaleError fallback against the live stack: seed a genuinely stale root key (rotate a shared root in a "lost" prior session, then attempt a further mutation with the old key still in memory) and confirm the top-down re-navigation recovers cleanly under real crypto, not mocks. This plan's unit coverage proves the WIRING and control flow (catch → delete → re-navigate → recover-or-report) and the zeroization invariant; it does not exercise the full network/crypto round-trip. The Open Question 2 residual (pure-revoke ancestor-mirror staleness) is a known, documented limitation of the fallback and is NOT expected to be exercised or fixed by 70-08 — a follow-up todo candidate for a later phase if rotation ever needs to re-seal its own root's ancestor mirror.

---
*Phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl*
*Completed: 2026-07-07*

## Self-Check: PASSED

Both modified files found on disk (`packages/sdk/src/client.ts`, `packages/sdk/src/__tests__/client-rotation.test.ts`); all three task commits (`c138160f4`, `7c06f9de0`, `1e6b0978a`) verified present in git log.
