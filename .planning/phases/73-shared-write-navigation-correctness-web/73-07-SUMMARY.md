---
phase: 73-shared-write-navigation-correctness-web
plan: 07
subsystem: ui
tags: [react, shared-folders, write-key, ipns, playwright]

requires:
  - phase: 73-06
    provides: consolidated restoreToBreadcrumbIndex helper (SC6) shared by navigateUp/navigateToBreadcrumb
provides:
  - NavStackEntry.writeKey + NavStackEntry.publishedNode carried per depth in the shared-nav stack
  - currentWriteKeyRef + zeroWriteKey active-depth writeKey lifecycle in useSharedNavigation.ts
  - refreshCurrentDepthWriteKey supplier for plan 73-08's SC4 refreshWriteAccess
  - Active (non-fixme) SC1 web-e2e case proving write-after-restore succeeds
affects: [73-08]

tech-stack:
  added: []
  patterns:
    - "Per-depth key ownership: exactly one of NavStackEntry.writeKey (suspended depth) or currentWriteKeyRef (active depth) ever owns a given writeKey buffer, never both"
    - "Per-depth publishedNode must travel with writeKey in the nav stack whenever a depth's cached SDK state can be re-seeded for a write op (write ops trust cached publishedNode, no network re-resolve)"

key-files:
  created: []
  modified:
    - apps/web/src/hooks/useSharedNavigationActions.ts
    - apps/web/src/hooks/useSharedNavigation.ts
    - apps/web/src/hooks/shared-folder-projection.ts
    - tests/web-e2e/tests/writable-shares.spec.ts

key-decisions:
  - "NavStackEntry gained both writeKey and publishedNode (not just writeKey per the plan's literal task list) -- publishedNode was a load-bearing pre-existing gap that only surfaces on write-after-restore, which is exactly this plan's new e2e case"
  - "refreshCurrentDepthWriteKey falls back to the retained currentWriteKeyRef for non-root depths (deeper resolveSharedSubfolderWriteKey needs the PARENT depth seeded, which is unavailable at the current depth's call site) -- documented limitation for 73-08 to build on"
  - "PLACEHOLDER_PUBLISHED_NODE exported from shared-folder-projection.ts as the single source of truth for the (unreachable in practice) fallback"

requirements-completed: [SC1]

coverage:
  - id: D1
    description: "NavStackEntry retains a writeKey per depth; restoreToBreadcrumbIndex transfers it (not the old isRootDepth/resolveSharedRootWriteKey re-derivation) so a restored non-root depth keeps real write capability"
    requirement: "SC1"
    verification:
      - kind: e2e
        ref: "tests/web-e2e/tests/writable-shares.spec.ts#8.4b Bob navigates up one level then writes from the restored subfolder (SC1)"
        status: pass
      - kind: other
        ref: "pnpm --filter @cipherbox/web exec tsc -b"
        status: pass
    human_judgment: false
  - id: D2
    description: "Every writeKey buffer has a matching zero-on-exit site (new-share entry, restore active-abandon + discarded-deeper-entries, navigate-to-root, unmount); resolveSharedRootWriteKey/resolveSharedSubfolderWriteKey implementations left unmodified"
    verification:
      - kind: other
        ref: "manual code audit — see file-header zeroization audit comment in useSharedNavigationActions.ts"
        status: pass
    human_judgment: false
  - id: D3
    description: "NavStackEntry also carries publishedNode (correctness fix discovered during verification) so write ops don't seed the SDK's placeholder envelope after restore"
    verification:
      - kind: e2e
        ref: "tests/web-e2e/tests/writable-shares.spec.ts full suite (30/30 passed locally)"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-10
status: complete
---

# Phase 73 Plan 07: Nav-stack writeKey + publishedNode restore correctness Summary

**NavStackEntry now carries both writeKey and publishedNode per depth so navigate-up/breadcrumb restore into a deep write-shared subfolder succeeds, with a full zero-on-every-exit-path audit for the new key buffer.**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-07-10T21:32:02+02:00 (base commit 921235edd)
- **Completed:** 2026-07-10T21:54:31+02:00
- **Tasks:** 2 (both completed; Task 1 required a correctness follow-up commit)
- **Files modified:** 4

## Accomplishments

- `NavStackEntry` gained `writeKey: Uint8Array | null` and `publishedNode: PublishedNode`; `useSharedNavigation.ts` gained a `currentWriteKeyRef` mirroring `ipnsPrivateKeyRef` plus a `zeroWriteKey()` helper.
- `restoreToBreadcrumbIndex` (the single helper shared by `navigateUp`/`navigateToBreadcrumb` from plan 73-06) now TRANSFERS the target depth's stored `writeKey` and `publishedNode` instead of the old `isRootDepth` branch that only ever re-derived a writeKey for a root-depth landing (and always re-seeded a placeholder `publishedNode`, regardless of depth).
- Every writeKey buffer has a matching zero site: `navigateToShare` (new-share entry), `navigateToSubfolder` (transfer on descent, no zero), `restoreToBreadcrumbIndex` (active-depth abandon + discarded-deeper-entries), `navigateToRoot` (full stack sweep), and unmount (`useSharedNavigation.ts` cleanup effect).
- Exposed `refreshCurrentDepthWriteKey` — the supplier plan 73-08 wires as SC4's `refreshWriteAccess` — with a documented fallback for non-root depths.
- Un-fixme'd and verified `writable-shares.spec.ts`'s 8.4b case (descend-2/up-1/write); ran the full 30-test `writable-shares.spec.ts` suite locally against the docker stack — all 30 passed, including 8.4b.

## Task Commits

1. **Task 1: writeKey in NavStackEntry + capture/transfer + restore reads stored writeKey + zeroization audit** - `fe3b01d37` (feat)
2. **Task 1 follow-up (correctness fix found during verification) + Task 2: finalize the SC1 web-e2e case** - `696699cdc` (feat)

**Plan metadata:** committed together with this SUMMARY (see final commit).

## Files Created/Modified

- `apps/web/src/hooks/useSharedNavigationActions.ts` - `NavStackEntry.writeKey`/`.publishedNode`; `currentWriteKeyRef` threaded through `SharedNavigationActionsParams`; `navigateToShare`/`navigateToSubfolder`/`navigateToRoot`/`restoreToBreadcrumbIndex` updated for capture/transfer/zero; new `refreshCurrentDepthWriteKey`; file-header zeroization audit comment
- `apps/web/src/hooks/useSharedNavigation.ts` - `currentWriteKeyRef` + `zeroWriteKey()`; `navStackRef` entry shape extended with `writeKey`/`publishedNode`; unmount cleanup extended; `refreshCurrentDepthWriteKey` added to the hook's return type
- `apps/web/src/hooks/shared-folder-projection.ts` - `PLACEHOLDER_PUBLISHED_NODE` exported (was module-private) so the nav-actions hook can reuse it as the capture-fallback
- `tests/web-e2e/tests/writable-shares.spec.ts` - 8.4b case un-fixme'd (`test.fixme` → `test`), comment updated to reflect the gap being closed

## Decisions Made

- Extended scope to also carry `publishedNode` in `NavStackEntry` (not just `writeKey` as the plan's task list literally specified) — see Deviations below for why this was required to meet SC1's own acceptance criteria.
- `refreshCurrentDepthWriteKey`'s non-root fallback re-seeds from the retained `currentWriteKeyRef` rather than attempting a parent-dependent `resolveSharedSubfolderWriteKey` re-derivation, since the parent depth is not available at this call site (documented in the function's doc comment for 73-08 to build on).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Restore also needed to carry `publishedNode`, not just `writeKey`**

- **Found during:** Task 2 verification (first full local run of the un-fixme'd 8.4b case)
- **Issue:** After landing Task 1 (writeKey-only restore), the SC1 e2e case failed: the upload after an up-one-level restore never appeared, and the shared folder view showed `// ERROR: Decryption failed`. Root cause: `uploadToSharedFolder`/`createSharedSubfolder`/etc. (`client.ts` `buildSharedWriteContextFromState`) trust `SharedFolderState.publishedNode` directly with **no** network re-resolve (unlike `updateSharedFile`, which does re-resolve). `restoreToBreadcrumbIndex`'s `seedActiveSharedFolder` call never passed a `publishedNode` override (true before this plan too), so `seedSharedFolder` fell back to `PLACEHOLDER_PUBLISHED_NODE` (an all-zero/empty stub) for the restored depth — the very first write there always failed to unseal, even with the now-correct writeKey. This gap was invisible before this plan because no prior test performed a write immediately after a restore (all prior tests either read-only after restore, or wrote only after a fresh re-descent, which always supplies a real `publishedNode`).
- **Fix:** Added `publishedNode: PublishedNode` to `NavStackEntry`; `navigateToSubfolder` now captures the CURRENT depth's live `publishedNode` from `getSdkClient().getSharedFolderState(currentShareId)` right before pushing (falling back to the (unreachable in practice) `PLACEHOLDER_PUBLISHED_NODE` if somehow unset); `restoreToBreadcrumbIndex` now passes `target.publishedNode` to `seedActiveSharedFolder` instead of omitting the field.
- **Files modified:** `apps/web/src/hooks/useSharedNavigationActions.ts`, `apps/web/src/hooks/useSharedNavigation.ts`, `apps/web/src/hooks/shared-folder-projection.ts` (exported the existing `PLACEHOLDER_PUBLISHED_NODE` constant for reuse)
- **Verification:** `pnpm --filter @cipherbox/web exec tsc -b` clean; full local `writable-shares.spec.ts` suite (30 tests) passed, including the new 8.4b case
- **Committed in:** `696699cdc` (Task 1 follow-up, bundled with Task 2's un-fixme commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — bug)
**Impact on plan:** Necessary for SC1's own acceptance criteria ("a write into a deep shared subfolder succeeds after navigate-up / breadcrumb restore") to actually hold. No scope creep — fix landed inside the same two files the plan already targeted, plus a one-line export in a third file the plan already referenced in `<read_first>`.

## Issues Encountered

None beyond the deviation above — see Deviations from Plan for the full root-cause writeup.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 73-08 (SC4 `refreshWriteAccess`) can consume `refreshCurrentDepthWriteKey` directly; its doc comment already documents the non-root-depth fallback behavior 73-08 should be aware of.
- No blockers for 73-08/73-09.

---

*Phase: 73-shared-write-navigation-correctness-web*
*Completed: 2026-07-10*
