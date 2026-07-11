---
phase: 77-crypto-hygiene-and-terminology-canonicalization
plan: 06
subsystem: sdk
tags: [dead-code-removal, sdk, share, api-client, typescript]

# Dependency graph
requires:
  - phase: 68
    provides: v2.0 encrypted-key grant model (encryptedReadKey/encryptedWriteKey) that superseded the per-recipient share re-wrap fan-out
provides:
  - Dead ShareCallbacks type + shareCallbacks config field removed from packages/sdk public surface
  - Dead addShareKeysFn field removed from SharedWriteContext/SharedWriteContextParams/SharedFolderState and every construction site (client.ts, web hooks)
  - Orphaned updateSharePermission/updatePermissionFn SDK wrapper removed (no live caller)
  - Orphaned generated UpdatePermissionDto/UpdatePermissionDtoPermission api-client models removed (no backing openapi.json route)
  - Deprecated ReceivedShare.encryptedIpnsKey field removed (unread)
  - Verification that the discarded per-upload ECIES wrapKey (todo #11) was already retired under READ-03 — no code change needed
affects: [sdk-terminology-cleanup, api-client-generation]

# Tech tracking
tech-stack:
  added: []
  patterns: [Deleting now-meaningless .not.toHaveBeenCalled() test assertions alongside the field they assert on, rather than leaving stale coverage]

key-files:
  created: []
  modified:
    - packages/sdk/src/types.ts
    - packages/sdk/src/index.ts
    - packages/sdk/src/share/context.ts
    - packages/sdk/src/share/shared-write.ts
    - packages/sdk/src/share/index.ts
    - packages/sdk/src/client.ts
    - apps/web/src/hooks/shared-folder-projection.ts
    - apps/web/src/hooks/useSharedNavigation.ts
    - apps/web/src/hooks/useSharedNavigationActions.ts
    - apps/web/src/hooks/useAuth.ts
    - apps/web/src/hooks/useFolderMutations.ts
    - apps/web/src/stores/share.store.ts
    - packages/api-client/src/models/index.ts

key-decisions:
  - "SharedFolderState.addShareKeysFn (types.ts) was removed alongside SharedWriteContext.addShareKeysFn even though only the latter was named in the plan's action text — the acceptance-criteria grep required zero occurrences across packages/sdk/src, and the SharedFolderState field was the source construction sites read from"
  - "Reworded 2 stale doc comments (useFolderMutations.ts, useAuth.ts) that referenced the literal string 'shareCallbacks' in prose — kept the documentation intent but dropped the dead-symbol name so the plan's whole-tree drift grep is clean"
  - "No pnpm api:generate run for the UpdatePermissionDto removal — these are orphaned generated artifacts with zero matching route in openapi.json; regeneration would not recreate them"
  - "Task 3 (wrapKey audit) required no code change — every wrapKey( call site across packages/sdk-core and packages/sdk flows its result into a persisted/returned field; the one call that WAS discarded (per-upload ECIES wrap of fileKey) was already retired under READ-03, documented by a 'retired' comment in upload/index.ts"

requirements-completed: [SC3]

coverage:
  - id: D1
    description: "ShareCallbacks type, shareCallbacks config field, and addShareKeysFn removed end-to-end from packages/sdk and apps/web, including dead test assertions"
    requirement: "SC3"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk test (51 files, 413 tests passed)"
        status: pass
      - kind: other
        ref: "grep -rn 'ShareCallbacks|addShareKeysFn|shareCallbacks' packages/sdk/src apps/web/src -> 0 matches"
        status: pass
    human_judgment: false
  - id: D2
    description: "packages/sdk builds and apps/web typechecks against the rebuilt sdk dist after the removal"
    requirement: "SC3"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk build"
        status: pass
      - kind: other
        ref: "pnpm --filter @cipherbox/web exec tsc -b --force"
        status: pass
    human_judgment: false
  - id: D3
    description: "Orphaned updateSharePermission/updatePermissionFn and UpdatePermissionDto/UpdatePermissionDtoPermission generated models removed with zero references remaining"
    requirement: "SC3"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk test (51 files, 411 tests passed after removing the 2 updateSharePermission-only tests)"
        status: pass
      - kind: other
        ref: "pnpm --filter @cipherbox/api-client typecheck; grep -rn 'updateSharePermission|updatePermissionFn' packages/sdk/src -> 0; test ! -f packages/api-client/src/models/updatePermissionDto.ts"
        status: pass
    human_judgment: false
  - id: D4
    description: "Todo #11 (discarded per-upload ECIES wrapKey) verified already-satisfied — no orphaned wrapKey( result found across packages/sdk-core and packages/sdk"
    requirement: "SC3"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk-core test (32 files, 370 tests passed)"
        status: pass
      - kind: other
        ref: "grep -c 'retired' packages/sdk-core/src/upload/index.ts -> 1; manual audit of every wrapKey( call site (10 sites across sdk-core/sdk) confirmed each result flows to a returned/persisted field"
        status: pass
    human_judgment: false

# Metrics
duration: 20min
completed: 2026-07-11
status: complete
---

# Phase 77 Plan 06: Retire Dead SDK Share Scaffolding Summary

**Removed the largest dead-code surface in phase 77 — ShareCallbacks/shareCallbacks/addShareKeysFn, the orphaned updateSharePermission SDK wrapper, and the orphaned UpdatePermissionDto generated api-client models — and confirmed the discarded per-upload ECIES wrapKey (todo #11) was already retired under READ-03.**

## Performance

- **Duration:** ~20 min
- **Tasks:** 3 completed (1 verification-only, no code change)
- **Files modified:** 21 (13 in Task 1, 8 in Task 2, 0 in Task 3)

## Accomplishments

- Removed the `ShareCallbacks` type, its public re-export, and the `shareCallbacks?` config field from `packages/sdk` — the v2.0 encrypted-key grant model (SC#2/D-12) superseded the per-recipient share re-wrap fan-out
- Removed `addShareKeysFn` from `SharedWriteContext`, `SharedWriteContextParams`, and `SharedFolderState`, and updated every construction site (`client.ts`'s 3 no-op sites, `shared-folder-projection.ts`, `useSharedNavigation.ts`, `useSharedNavigationActions.ts`)
- Deleted the now-meaningless `.not.toHaveBeenCalled()` mock assertions across 8 SDK test files and 1 web test file, rather than leaving stale coverage of a deleted field
- Removed the orphaned `updateSharePermission`/`updatePermissionFn` SDK wrapper (no live caller in `apps/web` or `client.ts` — only its own test) and its barrel re-exports
- Deleted the orphaned generated `UpdatePermissionDto`/`UpdatePermissionDtoPermission` api-client models (zero matching route in `openapi.json`) and their barrel exports
- Removed the deprecated `ReceivedShare.encryptedIpnsKey` field (unread anywhere in the web app)
- Verified via a full `wrapKey(` call-site audit across `packages/sdk-core` and `packages/sdk` that no discarded per-upload ECIES wrap exists — the upload path was already retired under READ-03 (documented by the file-header comment in `upload/index.ts`)

## Task Commits

Each task was committed atomically:

1. **Task 1: Remove ShareCallbacks + shareCallbacks + addShareKeysFn end-to-end** - `172ce0c2e` (feat)
2. **Task 2: Remove orphaned updateSharePermission + UpdatePermissionDto generated models** - `ea0d7504c` (feat)
3. **Task 3: Verify the discarded per-upload ECIES wrapKey is already gone** - verification-only, no code change (documented here)

**Follow-up fixup:** `6181ea3a2` (docs) — reworded a doc comment in `share.store.ts` that still named the now-deleted `updateSharePermission` wrapper literally, to keep the plan's whole-tree drift grep clean.

_Note: no `docs: complete plan` metadata commit is separate from this SUMMARY commit — it follows immediately after this file is written._

## Files Created/Modified

- `packages/sdk/src/types.ts` - Removed `ShareCallbacks` type, `shareCallbacks?` field, `SharedFolderState.addShareKeysFn`; dropped now-unused `SentShareInfo`/`ShareKeyType` imports
- `packages/sdk/src/index.ts` - Removed `ShareCallbacks` and `updateSharePermission` re-exports
- `packages/sdk/src/share/context.ts` - Removed `addShareKeysFn` from `SharedWriteContextParams` and `buildSharedWriteContext`
- `packages/sdk/src/share/shared-write.ts` - Removed `addShareKeysFn` from `SharedWriteContext` + 6 stale doc-comment references; removed `updateSharePermission`/`updatePermissionFn`
- `packages/sdk/src/share/index.ts` - Removed `updateSharePermission` re-export
- `packages/sdk/src/client.ts` - Removed 3 `addShareKeysFn` construction sites and their doc-comment mentions
- `apps/web/src/hooks/shared-folder-projection.ts` - Removed `addShareKeysFn` from `SeedSharedFolderArgs` and `seedSharedFolder`
- `apps/web/src/hooks/useSharedNavigation.ts` - Simplified `seedActiveSharedFolder` (no more `Omit<..., 'addShareKeysFn'>` + no-op injection)
- `apps/web/src/hooks/useSharedNavigationActions.ts` - Updated `seedActiveSharedFolder` param type
- `apps/web/src/hooks/useAuth.ts`, `apps/web/src/hooks/useFolderMutations.ts` - Reworded stale comments naming the removed `shareCallbacks` field
- `apps/web/src/stores/share.store.ts` - Removed deprecated `encryptedIpnsKey` field; reworded doc comment
- `packages/api-client/src/models/index.ts` - Removed `updatePermissionDto`/`updatePermissionDtoPermission` barrel exports
- `packages/api-client/src/models/updatePermissionDto.ts`, `updatePermissionDtoPermission.ts` - Deleted (orphaned generated models)
- 9 test files (`packages/sdk/src/__tests__/{context,shared-write,client-shared-write,enumerate-shared-subtree,folder-listing,move-in-shared-folder,resolve-shared-subfolder-write-key,shared-folder-tree,upload-batch}.test.ts`, `apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts`) - Removed mock setup and assertions referencing the deleted fields/functions

## Decisions Made

- `SharedFolderState.addShareKeysFn` (types.ts) was removed alongside `SharedWriteContext.addShareKeysFn` — the plan's action text named only the latter, but the acceptance-criteria grep (`addShareKeysFn` → 0 matches in `packages/sdk/src`) required both, and `SharedFolderState` was the actual source construction sites read the callback from
- Reworded 2 stale doc comments (`useFolderMutations.ts`, `useAuth.ts`) that named `shareCallbacks` literally in prose, to satisfy the plan's own grep-based acceptance criteria while preserving the documentation intent
- No `pnpm api:generate` run for the `UpdatePermissionDto` removal — confirmed via `grep -c "UpdatePermissionDto" openapi.json` returning 0 that these are orphaned generated artifacts with no source route; regeneration would not recreate them
- Task 3 required no code change — audited all 10 `wrapKey(` call sites across `packages/sdk-core`/`packages/sdk` and confirmed every result is consumed (assigned to a returned or persisted field); the one call that WAS historically discarded (per-upload ECIES wrap of `fileKey`) was already retired under READ-03, documented in `upload/index.ts`'s header comment

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Unused `vi` import after deleting the only `vi.fn()` call in shared-folder-tree.test.ts**
- **Found during:** Task 1 (pre-commit eslint hook)
- **Issue:** Removing the `addShareKeysFn: vi.fn()...` mock line left `vi` imported-but-unused, tripping `@typescript-eslint/no-unused-vars`
- **Fix:** Dropped `vi` from the `import { describe, it, expect } from 'vitest'` line
- **Files modified:** `packages/sdk/src/__tests__/shared-folder-tree.test.ts`
- **Verification:** `pnpm --filter @cipherbox/sdk exec eslint src/__tests__/shared-folder-tree.test.ts` clean; sdk build + full test suite green
- **Committed in:** `172ce0c2e` (part of Task 1 commit)

**2. [Rule 2 - Missing Critical] Reworded doc comment retaining a literal `updateSharePermission` reference after its removal**
- **Found during:** Post-Task-2 whole-tree verification grep (the plan's overall `<verification>` block, distinct from Task 2's narrower acceptance criteria)
- **Issue:** My own updated doc comment in `share.store.ts` (Task 2) named the now-deleted `updateSharePermission` wrapper literally, which the plan's full verification grep across `apps/web/src` would still catch
- **Fix:** Reworded to "permission-update SDK wrapper" — same documentation intent, no dead-symbol name
- **Files modified:** `apps/web/src/stores/share.store.ts`
- **Verification:** `grep -rn "ShareCallbacks|addShareKeysFn|shareCallbacks|updateSharePermission|UpdatePermissionDto" packages/sdk/src apps/web/src packages/api-client/src` → 0 matches
- **Committed in:** `6181ea3a2` (separate follow-up commit, since Task 2's commit had already landed)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 missing-critical/drift-cleanup)
**Impact on plan:** Both fixes were mechanical hygiene follow-ups required to satisfy the plan's own acceptance criteria and verification block. No scope creep — no behavior changed.

## Issues Encountered

- Two `git commit` invocations reported a 2-minute tool timeout (exit 143) while the pre-commit hook (lint-staged + husky + 1Password GPG signing) was still running. Per project convention (never retry blindly), verified via `git log --oneline` after each timeout and confirmed both commits had actually landed (`172ce0c2e`, `ea0d7504c`). No data was lost or duplicated.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All grep-based acceptance criteria for dead-code removal are clean (0 matches for `ShareCallbacks`, `addShareKeysFn`, `shareCallbacks`, `updateSharePermission`, `UpdatePermissionDto` across `packages/sdk/src`, `apps/web/src`, `packages/api-client/src`)
- `packages/sdk` builds and its full unit suite passes (51 files, 413→411 tests after removing 2 dead tests)
- `packages/sdk-core` full unit suite passes (32 files, 370 tests) — confirms Task 3's wrapKey audit did not disturb behavior
- `apps/web` typechecks cleanly against the rebuilt `packages/sdk` dist (`tsc -b --force`)
- `packages/api-client` typechecks cleanly after the orphaned model deletion
- Ready for the next phase-77 plan (77-07)

---
*Phase: 77-crypto-hygiene-and-terminology-canonicalization*
*Completed: 2026-07-11*
