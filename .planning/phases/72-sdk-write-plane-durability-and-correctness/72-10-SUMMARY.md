---
phase: 72-sdk-write-plane-durability-and-correctness
plan: 10
subsystem: sdk
tags: [typescript, sdk, refactor, dedup, write-plane, ipns]

# Dependency graph
requires:
  - phase: 72-sdk-write-plane-durability-and-correctness
    provides: "Plan 08's write-chain hop-walk consolidation (hasRealWriteKey single definition) and Plan 04's SC#2 fail-closed getWriteBodyParams unification (precondition for this plan's bin re-point)"
provides:
  - "A single version-op core (runFileVersionOp) shared by replaceFile/restoreFileVersion/deleteFileVersion in client.ts"
  - "A single getWriteBodyParams/adoptPublishedFolderState/hasRealWriteKey implementation (packages/sdk/src/write-body-params.ts) shared by CipherBoxClient and the bin operations module"
affects: [sdk-write-plane, sdk-bin-operations, file-versioning]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Shared private core + thin public delegators for near-identical class methods (runFileVersionOp)"
    - "Standalone shared module for logic that must be called from both a stateful class (this.ctx/this.folderTree) and stateless free functions (explicit ctx/folderTree params)"

key-files:
  created:
    - packages/sdk/src/write-body-params.ts
  modified:
    - packages/sdk/src/client.ts
    - packages/sdk/src/bin/index.ts

key-decisions:
  - "runFileVersionOp is NOT wrapped in withOperation itself -- each public method (replaceFile/restoreFileVersion/deleteFileVersion) keeps its own withOperation(name, ...) wrapper for correct per-operation telemetry attribution, and calls the shared core from inside that callback."
  - "deletedCid stays out of the shared core (it's pure passthrough, never enters the updateFileMetadata publish call) -- deleteFileVersion folds it back into the result after the core returns."
  - "The shared write-body-params.ts module standardizes on the inline resolveIpnsRecord+fetchFromIpfs+JSON.parse resolve (bin/index.ts's existing style) rather than client.ts's private resolvePublishedNode wrapper, since signatureVerified (the only extra field resolvePublishedNode returns) was never consumed by getWriteBodyParams -- confirmed behaviorally identical per 72-04's note."
  - "versionIndex parameters (restoreFileVersion/deleteFileVersion) are now _versionIndex (underscore-prefixed) instead of a dead `void versionIndex;` statement -- satisfies both eslint's argsIgnorePattern and tsconfig's noUnusedParameters without a suppression statement."

requirements-completed: [SC#6]

coverage:
  - id: D1
    description: "replaceFile/restoreFileVersion/deleteFileVersion share one extracted version-op core (runFileVersionOp); dead void versionIndex slots removed"
    requirement: "SC#6"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk test (389 passed, baseline maintained)"
        status: pass
    human_judgment: false
  - id: D2
    description: "bin/index.ts's getWriteBodyParams/adoptPublishedFolderState literal copies deleted; both bin/index.ts and client.ts import/delegate to a single packages/sdk/src/write-body-params.ts implementation"
    requirement: "SC#6"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk test (389 passed) -- includes get-write-body-params-fail-closed.test.ts exercising both the client.ts path (via renameItem) and the bin/index.ts path (via addToBin)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Full web-e2e (writable-shares + move-restore-content) green on the live stack -- phase-final gate per plan's <verification> section"
    verification: []
    human_judgment: true
    rationale: "Plan explicitly scopes web-e2e verification to phase-final, not per-plan; requires the live docker stack and is not run by this executor. Deferred to phase-level verification."

# Metrics
duration: 10min
completed: 2026-07-10
status: complete
---

# Phase 72 Plan 10: Version-Op Core + getWriteBodyParams Dedup Summary

**Extracted the shared body of replaceFile/restoreFileVersion/deleteFileVersion into one `runFileVersionOp` core, and collapsed the two textually-identical `getWriteBodyParams`/`adoptPublishedFolderState` copies (client.ts + bin/index.ts) into a single `packages/sdk/src/write-body-params.ts` module.**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-07-10T15:21:00Z
- **Completed:** 2026-07-10T15:30:39Z
- **Tasks:** 2
- **Files modified:** 2 (client.ts, bin/index.ts); 1 created (write-body-params.ts)

## Accomplishments

- Extracted a private `runFileVersionOp` core in `client.ts` capturing the identical body of `replaceFile`, `restoreFileVersion`, and `deleteFileVersion`: `requireFolder` → `resolveFileWriteChainKeys` → the 14-field `updateFileMetadata` publish → the `maybeRepublishFolderForFileMigration` piggyback → the 3-key zeroing `finally`. Only `createVersion` (and, for delete, the passthrough `deletedCid`) vary across the three public methods now.
- Removed the dead `void versionIndex;` statements by underscore-prefixing the unused `versionIndex` parameter (`_versionIndex`) in `restoreFileVersion`/`deleteFileVersion` — satisfies `noUnusedParameters` and eslint's `argsIgnorePattern: '^_'` without a suppression statement.
- Created `packages/sdk/src/write-body-params.ts` exporting `hasRealWriteKey`, `getWriteBodyParams`, and `adoptPublishedFolderState` as standalone functions taking explicit `ctx`/`folderTree` params. `CipherBoxClient`'s private methods now delegate to these (`this.ctx`/`this.folderTree` threaded through); `bin/index.ts` imports them directly (it never had `this` to read).
- Reconciled the one behavioral divergence 72-04-SUMMARY.md flagged: `client.ts`'s `getWriteBodyParams` previously resolved via the private `resolvePublishedNode` helper (which also returns `signatureVerified`, unused here) while `bin/index.ts` inlined `resolveIpnsRecord` + `fetchFromIpfs` + `JSON.parse` directly. The shared module standardizes on the inline form (bin's pre-existing style) since the two were already confirmed behaviorally identical for this call site.

## Task Commits

Each task was committed atomically:

1. **Task 1: Extract the shared version-op core** - `e5c62296f` (refactor)
2. **Task 2: Re-point bin/index.ts at the client helpers** - `12b435525` (refactor)

**Plan metadata:** (this commit)

## Files Created/Modified

- `packages/sdk/src/write-body-params.ts` - NEW: shared `hasRealWriteKey` / `getWriteBodyParams` / `adoptPublishedFolderState` implementation, imported by both `client.ts` and `bin/index.ts`
- `packages/sdk/src/client.ts` - Added private `runFileVersionOp` core; `replaceFile`/`restoreFileVersion`/`deleteFileVersion` now delegate to it; `getWriteBodyParams`/`adoptPublishedFolderState` are now thin delegators to `write-body-params.ts`; removed the local `hasRealWriteKey` definition (now imported)
- `packages/sdk/src/bin/index.ts` - Deleted the local `getWriteBodyParams`/`adoptPublishedFolderState` copies (and the now-unused `unsealNode`/`PublishedNode` imports they required); imports the shared implementations from `../write-body-params` instead

## Decisions Made

- `runFileVersionOp` does not wrap `withOperation` itself — each public method keeps its own `withOperation('replaceFile' | 'restoreFileVersion' | 'deleteFileVersion', ...)` call so `operation:start`/`operation:end`/`error` events and `onOperationStart`/`onOperationEnd` callbacks still attribute to the correct per-op name.
- `deletedCid` stays out of the shared core's params/return type since it never enters the `updateFileMetadata` publish call — `deleteFileVersion` folds it into the final `{ deletedCid, prunedCids }` result after calling the core.
- The shared `write-body-params.ts` module standardizes the IPNS-resolve path on the inline `resolveIpnsRecord` + `fetchFromIpfs` + `JSON.parse` sequence (matching `bin/index.ts`'s pre-existing style) rather than `client.ts`'s private `resolvePublishedNode` wrapper — the extra `signatureVerified` field that wrapper returns was never consumed by `getWriteBodyParams`, so this is a pure consolidation with no behavior change.

## Deviations from Plan

None — plan executed exactly as written. The `void versionIndex;` removal used underscore-prefixing (`_versionIndex`) rather than deleting the parameter entirely, since the parameter is part of the public method signature callers rely on positionally; this satisfies the plan's acceptance criterion (`grep -c 'void versionIndex' ... returns 0`) without changing the public API shape.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SC#6 (the last self-documented copy-paste in the write plane) is now fully closed: one version-op core, one `getWriteBodyParams`/`adoptPublishedFolderState`/`hasRealWriteKey`.
- `pnpm --filter @cipherbox/sdk test` (389 passed, 36 skipped, baseline maintained) and `pnpm --filter @cipherbox/sdk build` (tsup + `tsc -p tsconfig.build.json`) both green after each task.
- Full-package `tsc --noEmit -p tsconfig.json` (which includes test files) surfaces pre-existing, unrelated type-drift errors in several `__tests__/*.test.ts` files (stale `@cipherbox/core` type names like `FolderChild`/`FolderEntry`, missing `VaultInit.rootFolderKey`, etc.) — these predate this plan's changes and are already tracked in the untracked todo `.planning/todos/pending/2026-07-10-typecheck-all-tests-in-ci-and-fix-vitest-v3-mock-drift.md`. Out of scope per the executor's scope-boundary rule (pre-existing, unrelated-file drift).
- Phase-final gate (full web-e2e writable-shares + move-restore-content on the live stack) is still outstanding — this and Plan 08 were called out in the plan as the high-blast-radius refactor slices requiring that gate before the phase is considered fully closed.

---
*Phase: 72-sdk-write-plane-durability-and-correctness*
*Completed: 2026-07-10*

## Self-Check: PASSED

- FOUND: packages/sdk/src/write-body-params.ts
- FOUND commit: e5c62296f
- FOUND commit: 12b435525
- `grep -c 'void versionIndex' packages/sdk/src/client.ts` = 0
- `grep -c 'Mirrors CipherBoxClient' packages/sdk/src/bin/index.ts` = 0
