---
phase: 68-web-integration-rotation-ux-and-durable-client-state
plan: 09
subsystem: ui
tags: [react, zustand, error-handling, rotation, ux]

requires:
  - phase: 68 (68-05)
    provides: ReconcileStaleError thrown by CipherBoxClient's reconcile-before-publish guard (SC#3/D-04)
  - phase: 68 (68-01/68-06)
    provides: SequenceRegressionError/GenerationRegressionError thrown by the durable rotation high-water enforceResolved gate, wired into the web IPNS resolve path
  - phase: 65
    provides: CannotWriteUntilRefetchError thrown by the write-body shared-write operations when a co-writer's target was rotated out (WRITE-03/D-03)
provides:
  - runWithFailureUx(mutationFn, opts) — classifies fail-closed SDK errors into the exact UI-SPEC toast + bounded-retry policy
  - useFolderMutations/useFileOperations/useFileBrowserActions routed through the classifier on their SDK-adjacent call sites
affects: [68-10 (web-e2e rotation-ux spec exercises every toast path added here)]

tech-stack:
  added: []
  patterns:
    - "runWithFailureUx wraps a single SDK client call (not the surrounding handler) so a retry re-invokes just that call, letting the SDK's own reconcile-before-publish re-check fresh network state each attempt"
    - "Classification lives in one hook; every mutation hook calls it at its own SDK/resolve call site rather than at the outermost UI action layer, so a defer/regression/stale-write error is toasted exactly once"

key-files:
  created:
    - apps/web/src/hooks/useMutationFailureUx.ts
  modified:
    - apps/web/src/hooks/useFolderMutations.ts
    - apps/web/src/hooks/useFileOperations.ts
    - apps/web/src/components/file-browser/useFileBrowserActions.ts
    - packages/sdk/src/index.ts
    - packages/sdk/src/share/index.ts

key-decisions:
  - "Wrapped only the direct client.X()/resolveIpnsRecord() call sites, not the whole handler bodies, so a bounded-backoff retry re-runs just the SDK call and inherits the SDK's own fresh reconcile check rather than replaying stale web-side state"
  - "Did not wrap useFileBrowserActions' delete/move/rename handlers a second time -- they delegate to the already-wrapped useFolderMutations callbacks, and double-wrapping would dispatch the same toast twice; instead wrapped its own direct resolveIpnsRecord call in handleSync, the one SDK-adjacent site not already covered"
  - "Exported ReconcileStaleError and CannotWriteUntilRefetchError from the @cipherbox/sdk barrel (Rule 3 blocking-issue fix) -- neither was previously importable outside the package, which is required for the instanceof classification this plan specifies"
  - "createFolder is intentionally NOT routed through runWithFailureUx -- the plan's truths/task-2 action text scope the wiring to delete/move/rename only"
  - "Bounded-backoff schedule is [2000, 4000, 8000, 16000]ms (4 retries after the initial attempt = 5 total attempts, summing to exactly 30000ms), matching D-06's '~5 attempts / ~30s' target as named constants"

requirements-completed: [ROT-07]

coverage:
  - id: D1
    description: "ReconcileStaleError retries with bounded backoff (~5 attempts/~30s), showing an info notice while retrying, and on exhaustion surfaces a terminal error notice with a Retry action -- mutation never applied, nothing queued"
    requirement: ROT-07
    verification:
      - kind: e2e
        ref: "68-10 web-e2e rotation-ux spec (defer -> Retry-exhausted toast)"
        status: unknown
    human_judgment: true
    rationale: "This plan explicitly adds no apps/web test file (docs/TESTING.md doctrine); the classification + retry timing is proven by the 68-10 web-e2e spec, not yet executed as part of this plan."
  - id: D2
    description: "SequenceRegressionError/GenerationRegressionError surface 'Stale data from server rejected.' immediately, per-mutation, with no retry"
    requirement: ROT-07
    verification:
      - kind: e2e
        ref: "68-10 web-e2e rotation-ux spec (regression toast)"
        status: unknown
    human_judgment: true
    rationale: "Proven by the 68-10 web-e2e spec, not executed as part of this plan; source-confirmed no-retry branch via code inspection."
  - id: D3
    description: "A stale/rotated-out write-descriptor failure surfaces 'Write failed — access may be out of date.' with a Refresh access action; if still failing after refresh, escalates to terminal 'Write access revoked.' with no action"
    requirement: WRITE-03
    verification:
      - kind: e2e
        ref: "68-10 web-e2e rotation-ux spec (co-writer Refresh-access / revoked-terminal)"
        status: unknown
    human_judgment: true
    rationale: "No live call site in this plan's three files currently throws CannotWriteUntilRefetchError (client.renameItem/moveItem/deleteItem don't yet route through the shared-write path); the classifier is generic/forward-compatible but this exact toast pair has not been runtime-exercised."
  - id: D4
    description: "IndexedDB-unavailable warning shows at most once per session"
    requirement: ROT-07
    verification:
      - kind: e2e
        ref: "68-10 web-e2e rotation-ux spec (D-08 one-time notice)"
        status: unknown
    human_judgment: true
    rationale: "Proven by the 68-10 web-e2e spec, not executed as part of this plan."

duration: 30min
completed: 2026-07-01
status: complete
---

# Phase 68 Plan 09: Fail-closed error classification + failure UX Summary

**A single `runWithFailureUx` hook classifies `ReconcileStaleError`, `SequenceRegressionError`/`GenerationRegressionError`, and `CannotWriteUntilRefetchError` into the exact UI-SPEC toast + bounded-retry policy, wired into the three delete/move/rename mutation call sites without re-implementing any upstream security check.**

## Performance

- **Duration:** ~30 min
- **Completed:** 2026-07-01
- **Tasks:** 2
- **Files modified:** 6 (1 created, 5 modified)

## Accomplishments
- `useMutationFailureUx.ts` classifies every fail-closed error the SDK/resolve layer can throw into the exact UI-SPEC copy: `Syncing latest state…` (info, retrying) / `Couldn't complete securely — retry.` (error, Retry action) for a deferred `ReconcileStaleError`; `Stale data from server rejected.` (error, no retry) for a sequence/generation regression; `Write failed — access may be out of date.` (error, Refresh access action) escalating to `Write access revoked.` (error, no action) for a stale/rotated-out write descriptor; `Secure cache unavailable — falling back to server verification.` (warning, once per session) for D-08.
- Bounded-backoff retry for the reconcile-defer path: 4 delays (`[2000, 4000, 8000, 16000]`ms) between 5 total attempts, summing to exactly 30s, exposed as named constants (`RECONCILE_RETRY_DELAYS_MS`, `RECONCILE_MAX_ATTEMPTS`). On exhaustion, the mutation is not applied and nothing is queued — the terminal toast's `Retry` action simply re-invokes `runWithFailureUx` fresh.
- `useFolderMutations.ts`'s rename/move/move-batch/delete/delete-batch SDK call sites now route through the classifier; `useFileOperations.ts`'s phase-65 stub is wrapped so the classifier is already in place once real file-update mutations land; `useFileBrowserActions.ts`'s background-sync `resolveIpnsRecord` call is wrapped as the one direct SDK-adjacent call site in that file not already covered by the wrapped `useFolderMutations` callbacks it delegates to.
- Exported `ReconcileStaleError` (from `packages/sdk/src/client.ts`) and `CannotWriteUntilRefetchError` (from `packages/sdk/src/share/shared-write.ts`) through the `@cipherbox/sdk` barrel so `instanceof` classification is possible from `apps/web` — neither was previously part of the package's public surface.

## Task Commits

Each task was committed atomically:

1. **Task 1: useMutationFailureUx — classify + bounded-backoff retry + action toasts** - `b62039a51` (feat)
2. **Task 2: Wire useMutationFailureUx into the three mutation hooks** - `82b0cd4ee` (feat)

_No TDD tasks in this plan — per docs/TESTING.md, apps/web is not unit-tested; both tasks used `tsc --noEmit` + source-grep/instanceof verification._

## Files Created/Modified
- `apps/web/src/hooks/useMutationFailureUx.ts` - New: `runWithFailureUx` classifier + bounded-backoff retry + toast dispatch
- `apps/web/src/hooks/useFolderMutations.ts` - Routed rename/move/move-batch/delete/delete-batch SDK calls through the classifier
- `apps/web/src/hooks/useFileOperations.ts` - Wrapped the phase-65 stub `handleUpdateFile` for forward-compatibility
- `apps/web/src/components/file-browser/useFileBrowserActions.ts` - Wrapped `handleSync`'s direct `resolveIpnsRecord` call
- `packages/sdk/src/index.ts` - Barrel now exports `ReconcileStaleError` and `CannotWriteUntilRefetchError`
- `packages/sdk/src/share/index.ts` - Re-exports `CannotWriteUntilRefetchError` from `./shared-write`

## Decisions Made
- Wrap the innermost SDK call, not the whole handler, so a retry re-invokes only the network-facing operation and benefits from the SDK's own fresh reconcile check each attempt (see key-decisions in frontmatter for full rationale).
- Single-wrap-per-error-path: `useFolderMutations` owns the wrap for delete/move/rename; `useFileBrowserActions` only wraps its own unwrapped `resolveIpnsRecord` call to avoid a duplicate toast for the same thrown error.
- `createFolder` intentionally excluded per the plan's explicit "delete/move/rename" scope.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Exported `ReconcileStaleError` and `CannotWriteUntilRefetchError` from the `@cipherbox/sdk` barrel**
- **Found during:** Task 1 (useMutationFailureUx implementation)
- **Issue:** The plan requires `instanceof ReconcileStaleError` / `instanceof CannotWriteUntilRefetchError` classification against errors "from `@cipherbox/sdk`", but neither class was re-exported from `packages/sdk/src/index.ts` (or, for the latter, from `packages/sdk/src/share/index.ts`) — `apps/web` could not import either without this change, which would have blocked the task entirely.
- **Fix:** Added `ReconcileStaleError` to the `export { CipherBoxClient, BinNotLoadedError, ... } from './client'` line, and added `CannotWriteUntilRefetchError` to `packages/sdk/src/share/index.ts`'s shared-write re-export block, then re-exported it through `packages/sdk/src/index.ts`'s `./share` export list. No behavior change — purely additive barrel exports.
- **Files modified:** `packages/sdk/src/index.ts`, `packages/sdk/src/share/index.ts`
- **Verification:** Rebuilt `@cipherbox/sdk` dist (`pnpm --filter @cipherbox/sdk build`, after rebuilding its workspace dependencies which had no dist yet in this fresh worktree) and confirmed both symbols appear in `packages/sdk/dist/index.d.ts`; `pnpm --filter @cipherbox/web exec tsc --noEmit` passes with the `instanceof` checks in place.
- **Committed in:** `b62039a51` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking-issue export fix)
**Impact on plan:** Necessary to make the plan's specified `instanceof` classification possible at all; no scope creep — purely additive exports, no behavior change to any existing consumer.

## Issues Encountered
- This worktree had no `node_modules` and no built `dist/` for any workspace package on start; ran `pnpm i` and `pnpm -r run build` (the latter for the sdk/sdk-core/core/crypto/api-client dependency chain — it also attempted the unrelated `apps/desktop` Tauri build, which failed on a missing signing key, but every package this plan depends on built successfully before that point) to get a working baseline for `tsc --noEmit`.
- No SDK call site in this plan's three files currently throws `CannotWriteUntilRefetchError` at runtime (that error only originates from the separate, out-of-scope `useSharedWriteOps.ts` shared-write path). The classifier still checks for it generically per the plan's spec; the D-01/WRITE-03 toast pair is therefore implemented but not yet runtime-exercised by any of the three wired hooks — flagged as `human_judgment: true` in the coverage block above.

## Known Stubs
None introduced by this plan. `useFileOperations.handleUpdateFile` was already a phase-65 stub (throws "not implemented") before this plan; it is now wrapped in `runWithFailureUx` but its behavior (always throwing) is unchanged.

## Threat Flags
None. This plan only surfaces already-enforced fail-closed decisions (68-01/68-05/68-06/65) as user-visible UX; it introduces no new network endpoint, auth path, file-access pattern, or schema change.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `runWithFailureUx` and its exact toast copy/action wiring are ready for 68-10's web-e2e rotation-ux spec to exercise all four classified paths end-to-end (defer→Retry-exhausted, regression, co-writer Refresh-access/revoked, D-08 one-time notice).
- The D-01/WRITE-03 co-writer path is classifier-ready but has no live call site yet in the three wired hooks; if a future phase routes `useFolderMutations`/`useFileBrowserActions` through the shared-write operations (or wires `useSharedWriteOps.ts` into this classifier), the toast pair will already work without further changes to `useMutationFailureUx.ts`.

---
*Phase: 68-web-integration-rotation-ux-and-durable-client-state*
*Completed: 2026-07-01*

## Self-Check: PASSED

All created/modified files and both task commit hashes (`b62039a51`, `82b0cd4ee`) verified present on disk / in git log.
