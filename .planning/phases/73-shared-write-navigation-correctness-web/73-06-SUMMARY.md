---
phase: 73-shared-write-navigation-correctness-web
plan: 06
subsystem: ui
tags: [react, shared-navigation, refactor, dead-code-removal]

# Dependency graph
requires:
  - phase: 68.1-writable-shares-write-key-recipient-and-desync-hardening
    provides: resolveSharedRootWriteKey / resolveSharedSubfolderWriteKey (untouched by this plan)
provides:
  - Single restoreToBreadcrumbIndex helper as the sole restore/re-seed landing
    spot for navigateUp and navigateToBreadcrumb
  - Dead resolveFolderIpnsPrivateKey write-share-key path fully removed
affects: [73-07-nav-stack-writekey-retention, 73-09-refresh-after-restore]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Single restore helper (restoreToBreadcrumbIndex) parameterized by
      crumbIndex, delegated to by both navigateUp (stack.length - 1) and
      navigateToBreadcrumb (its own crumbIndex) -- eliminates copy-paste risk
      for follow-on fixes."

key-files:
  created: []
  modified:
    - apps/web/src/hooks/useSharedNavigationActions.ts
    - apps/web/src/hooks/useSharedNavigation.ts
    - apps/web/src/hooks/useSharedWriteOps.ts

key-decisions:
  - "Replaced the dead resolveFolderIpnsPrivateKey call sites with a direct
    const ipnsPrivateKey = new Uint8Array(32) inline assignment (byte-identical
    behavior) rather than removing the ipnsPrivateKey field from the SDK seed
    contract -- smaller, safer diff."
  - "restoreToBreadcrumbIndex is itself a useCallback so navigateUp/
    navigateToBreadcrumb can list it as a stable dependency; navigateUp
    computes stack.length - 1 before delegating."

patterns-established:
  - "restoreToBreadcrumbIndex(crumbIndex) is the designated landing spot for
    SC1 (writeKey-from-stack) and SC2 (refresh-after-restore) in plans 73-07
    and 73-09 -- both future fixes land inside this one function."

requirements-completed: [SC6, SC7]

coverage:
  - id: D1
    description: "Dead folder-IPNS write-share-key path (resolveFolderIpnsPrivateKey, getShareKeys param, shareKeysCacheRef) removed from useSharedNavigationActions.ts/useSharedNavigation.ts; fetchShareKeys and resolveSharedRootWriteKey remain live"
    requirement: "SC7"
    verification:
      - kind: other
        ref: "grep -rn 'resolveFolderIpnsPrivateKey' apps/web/src (returns 0)"
        status: pass
      - kind: other
        ref: "pnpm --filter @cipherbox/web exec tsc -b"
        status: pass
    human_judgment: false
  - id: D2
    description: "navigateUp and navigateToBreadcrumb restore/re-seed logic consolidated into one restoreToBreadcrumbIndex helper; both delegate, no duplicated block remains"
    requirement: "SC6"
    verification:
      - kind: other
        ref: "pnpm --filter @cipherbox/web exec tsc -b"
        status: pass
    human_judgment: true
    rationale: "apps/web has zero unit tests (logic covered by web-e2e Playwright, main-push gated per repo convention); behavioral-neutrality of the extraction was verified by structural code-read (crumbIndex = stack.length-1 case algebraically matches the old navigateUp body) rather than an automated runtime assertion. A full local web-e2e run (writable-shares.spec.ts, shared-folder-desync.spec.ts) is the recommended regression gate before merge."

duration: 6min
completed: 2026-07-10
status: complete
---

# Phase 73 Plan 06: Shared-Nav Dead-Code Removal + Restore Consolidation Summary

**Removed the dead folder-IPNS write-share-key path in `useSharedNavigationActions.ts`/`useSharedNavigation.ts` and consolidated `navigateUp`/`navigateToBreadcrumb`'s duplicated restore logic into one `restoreToBreadcrumbIndex` helper.**

## Performance

- **Duration:** ~6 min
- **Started:** 2026-07-10T19:19:00Z
- **Completed:** 2026-07-10T19:25:00Z
- **Tasks:** 2 completed
- **Files modified:** 3 (`useSharedNavigationActions.ts`, `useSharedNavigation.ts`, `useSharedWriteOps.ts`)

## Accomplishments

- Deleted the vestigial `resolveFolderIpnsPrivateKey` async helper and its 4 call sites (`navigateToShare`, `navigateToSubfolder`, `navigateUp`, `navigateToBreadcrumb`), replacing each with the byte-identical `new Uint8Array(32)` zero-buffer it always produced (the underlying `fetchShareKeys` stub always returns `[]`).
- Removed the now-dead `getShareKeys` param/callback and `shareKeysCacheRef`/`ShareKeyCache` plumbing threading through both hooks, including the unmount `.clear()` cleanup call.
- Confirmed `fetchShareKeys`, `resolveSharedRootWriteKey`, and `resolveSharedSubfolderWriteKey` remain fully live and untouched (real shared-write signing keys come from the SDK's write-body, never this path).
- Extracted a single `restoreToBreadcrumbIndex(crumbIndex)` helper from the near-verbatim `navigateUp`/`navigateToBreadcrumb` restore blocks; `navigateUp` now delegates with `stack.length - 1`, `navigateToBreadcrumb` delegates with its own `crumbIndex`. All folderKey zeroing, restored-field assignment, breadcrumb slicing, and the `isRootDepth` writeKey re-derivation are preserved unchanged.

## Task Commits

Each task was committed atomically:

1. **Task 1 (SC7): delete the dead folder-IPNS write-share-key path** - `e50044fe1` (refactor)
2. **Task 2 (SC6): extract a single restore helper for navigateUp + navigateToBreadcrumb** - `6cb963e03` (refactor)

**Plan metadata:** committed alongside this SUMMARY (see final commit in worktree branch history).

## Files Created/Modified

- `apps/web/src/hooks/useSharedNavigationActions.ts` - Deleted `resolveFolderIpnsPrivateKey` + `ShareKeyCache` import; removed `getShareKeys`/`shareKeysCacheRef` from params; extracted `restoreToBreadcrumbIndex` helper; `navigateUp`/`navigateToBreadcrumb` now thin delegates.
- `apps/web/src/hooks/useSharedNavigation.ts` - Removed `getShareKeys` callback, `shareKeysCacheRef` ref, its unmount cleanup, and the now-unused `ShareKeyCache`/`fetchShareKeys` imports; stopped threading both into the actions params.
- `apps/web/src/hooks/useSharedWriteOps.ts` - Comment-only fix: updated `resolveFileIpnsKey`'s doc comment, which referenced the now-deleted `resolveFolderIpnsPrivateKey` by name, to satisfy the plan's "grep returns 0 across apps/web/src, code AND comments" acceptance bar. `resolveFileIpnsKey`/`fetchShareKeys` themselves are untouched (landmine: still the live file-ipns fallback).

## Decisions Made

- Zero-buffer inline assignment (`new Uint8Array(32)`) chosen over dropping the `ipnsPrivateKey` field from the SDK's `SeedSharedFolderArgs` contract — smaller, safer diff, per the plan's explicit guidance.
- `restoreToBreadcrumbIndex` implemented as its own `useCallback` (not a plain closure) so `navigateUp`/`navigateToBreadcrumb` can reference it as a stable dependency in their own `useCallback` arrays.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug/dangling reference] Fixed a stray doc-comment reference to the deleted `resolveFolderIpnsPrivateKey` in `useSharedWriteOps.ts`**
- **Found during:** Task 1 verification (`grep -rn "resolveFolderIpnsPrivateKey" apps/web/src` initially returned 1, not 0)
- **Issue:** `useSharedWriteOps.ts`'s `resolveFileIpnsKey` doc comment named the sibling folder-ipns helper by name as a cross-reference; after Task 1 deleted that helper, the comment was a dangling reference that violated the plan's explicit "code AND comments — no residual references" acceptance criterion.
- **Fix:** Reworded the comment to describe `resolveFileIpnsKey` as "the last live consumer of the `share_keys` fan-out" instead of naming the deleted function, without touching `resolveFileIpnsKey`'s logic, `fetchShareKeys`, or any other live call site (landmine preserved).
- **Files modified:** `apps/web/src/hooks/useSharedWriteOps.ts`
- **Verification:** `grep -rn "resolveFolderIpnsPrivateKey" apps/web/src` returns 0; `pnpm --filter @cipherbox/web exec tsc -b` passes.
- **Committed in:** `e50044fe1` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking — grep acceptance criterion)
**Impact on plan:** Comment-only fix outside the plan's declared `files_modified` list, but required to satisfy the plan's own stated verification command. No behavioral change, no scope creep into `resolveFileIpnsKey`'s logic or the live `fetchShareKeys` consumers.

## Issues Encountered

None beyond the deviation above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `restoreToBreadcrumbIndex` is now the single landing spot for plan 73-07 (SC1: nav-stack `writeKey` retention, replacing the `isRootDepth` branch) and plan 73-09 (SC2: `refreshSharedFolder`-after-restore) — both can edit this one function instead of two copies.
- Full local web-e2e regression (`writable-shares.spec.ts`, `shared-folder-desync.spec.ts`) recommended before merge to confirm the UI-behavior-neutral refactor holds at runtime (apps/web has no unit tests; typecheck-only verification was performed here per repo convention).
- No blockers for 73-07/73-08/73-09.

---
*Phase: 73-shared-write-navigation-correctness-web*
*Completed: 2026-07-10*
