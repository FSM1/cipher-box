---
phase: 73-shared-write-navigation-correctness-web
plan: 01
subsystem: testing
tags: [playwright, web-e2e, test-scaffolding, shared-folders, rotation-ux]

requires: []
provides:
  - "New `test.fixme` case in tests/web-e2e/tests/writable-shares.spec.ts (8.4b) covering the descend-2 / up-1 / write gap (SC1), for 73-07 to finalize"
  - "New `test.fixme` case in tests/web-e2e/tests/shared-folder-desync.spec.ts covering deeper-mutate-then-navigate-up freshness (SC2), for 73-09 to finalize"
  - "Restructured `test.fixme` D-01/WRITE-03 case in tests/web-e2e/tests/rotation-ux.spec.ts documenting the real classifier-driven flow (SC4), for 73-08 to finalize"
affects: [73-07-shared-write-nav-correctness, 73-08-writeops-classifier-wiring, 73-09-shared-folder-desync-fix]

tech-stack:
  added: []
  patterns:
    - "Wave-0 fixme scaffolding: author the acceptance-contract test body as `test.fixme(...)` with documented target steps + a comment pointing to the impl plan that removes the guard, reusing the analog test's existing multi-account harness rather than a new fixture/describe block"

key-files:
  created: []
  modified:
    - tests/web-e2e/tests/writable-shares.spec.ts
    - tests/web-e2e/tests/shared-folder-desync.spec.ts
    - tests/web-e2e/tests/rotation-ux.spec.ts

key-decisions:
  - "SC1 fixme case (8.4b) uploads a new file at the restored depth-1 folder to assert write success, rather than a rename, to avoid introducing a new RenameDialogPage import not already used in writable-shares.spec.ts"
  - "SC2 fixme case reuses the shared-folder-desync.spec.ts owner+grantee accounts from 1.1/1.2, added AFTER the existing SC#5/D-03 regression test (3.1) as a new Phase 4 block, keeping the file-level 'do NOT test.fixme this spec' comment scoped to the pre-existing permanent regression test above it, not the new WIP scaffold"
  - "SC4 restructure keeps the pre-73-08 direct-notification-injection code as commented-out reference text (not deleted, not live code) inside the same test.fixme body so 73-08 knows the exact toast copy/action contract it must preserve when wiring the real trigger"

patterns-established:
  - "Wave-0 test scaffolding pattern documented above (fixme + harness-reuse + impl-plan pointer comment)"

requirements-completed: [SC1, SC2, SC4]

coverage:
  - id: D1
    description: "writable-shares.spec.ts gains a discovered (not-yet-asserted) fixme case '8.4b' covering descend-2 / up-1 / write for SC1"
    requirement: "SC1"
    verification:
      - kind: e2e
        ref: "playwright test --list tests/writable-shares.spec.ts (case discovered at line 712, column :8 = fixme)"
        status: pass
    human_judgment: false
  - id: D2
    description: "shared-folder-desync.spec.ts gains a discovered fixme case covering deeper-mutate-then-navigate-up freshness for SC2"
    requirement: "SC2"
    verification:
      - kind: e2e
        ref: "playwright test --list tests/shared-folder-desync.spec.ts (case discovered at line 215, column :8 = fixme)"
        status: pass
    human_judgment: false
  - id: D3
    description: "rotation-ux.spec.ts's D-01/WRITE-03 case is restructured in place to a documented fixme skeleton for the real classifier-driven flow, citing plans 73-02/73-05/73-08"
    requirement: "SC4"
    verification:
      - kind: e2e
        ref: "playwright test --list tests/rotation-ux.spec.ts (case discovered at line 312, column :8 = fixme)"
        status: pass
    human_judgment: false

duration: 14min
completed: 2026-07-10
status: complete
---

# Phase 73 Plan 01: Wave 0 Web-E2E Scaffold Summary

**Three web-e2e Playwright specs gained `test.fixme` regression targets (descend-2/up-1/write for SC1, deeper-mutate-then-navigate-up for SC2, classifier-driven WRITE-03 for SC4) that impl plans 73-07/73-08/73-09 will fill.**

## Performance

- **Duration:** 14 min
- **Started:** 2026-07-10T21:06:44+02:00 (base commit)
- **Completed:** 2026-07-10T21:20:48+02:00
- **Tasks:** 2 completed
- **Files modified:** 3

## Accomplishments

- `tests/web-e2e/tests/writable-shares.spec.ts` gained a new `test.fixme` case ("8.4b") reusing test 8.3's depth-2 descent + Bob's harness: descend to depth 2, navigate UP exactly one level (not to root), then upload a file from the restored depth-1 folder and assert success — the exact gap 8.4 (full round-trip) doesn't cover.
- `tests/web-e2e/tests/shared-folder-desync.spec.ts` gained a new `test.fixme` case reusing the owner+grantee dual-account harness from 1.1/1.2: grantee descends into a new subfolder, owner mutates the depth left behind, grantee navigates up and the listing must reflect the fresh mutation.
- `tests/web-e2e/tests/rotation-ux.spec.ts`'s existing D-01/WRITE-03 test (previously a live `test()` using direct `useNotificationStore` injection) was restructured in place into a `test.fixme` skeleton documenting the real classifier-driven flow (tombstoned co-writer publish → `runWithFailureUx` → `CannotWriteUntilRefetchError` → toast), with an updated SCOPE NOTE citing plans 73-02, 73-05, and 73-08 as the enabling seams, and the prior direct-injection assertions preserved as commented-out reference text.
- All three files verified to still parse and discover correctly via `playwright test --list` (40 total tests across the 3 files; all pre-existing cases unchanged; the 3 new/restructured cases appear at column `:8`, Playwright's marker for `fixme`).

## Task Commits

Each task was committed atomically:

1. **Task 1: Scaffold SC1 (writable-shares) and SC2 (shared-folder-desync) fixme cases** - `33e43cb42` (test)
2. **Task 2: Restructure SC4 rotation-ux D-01/WRITE-03 case toward a classifier-driven flow (fixme)** - `ee1e2f4cf` (test)

**Plan metadata:** (this commit)

## Files Created/Modified

- `tests/web-e2e/tests/writable-shares.spec.ts` - added fixme case 8.4b (descend-2 / up-1 / write, SC1)
- `tests/web-e2e/tests/shared-folder-desync.spec.ts` - added fixme case (deeper-mutate-then-navigate-up freshness, SC2)
- `tests/web-e2e/tests/rotation-ux.spec.ts` - restructured D-01/WRITE-03 case in place into a fixme classifier-flow skeleton (SC4)

## Decisions Made

- Chose upload (not rename) for the SC1 fixme case's write assertion — avoids introducing a `RenameDialogPage` import not already present in `writable-shares.spec.ts`, and mirrors the existing 8.3 upload pattern exactly.
- Placed the SC2 fixme case as a new "Phase 4" block after the file's existing SC#5/D-03 permanent regression test (3.1), preserving that test's own "do NOT test.fixme this spec" comment scope (it refers to the existing 2.1/3.1 regression test, not new WIP additions to the same file).
- Kept the SC4 restructure's pre-73-08 direct-injection code as commented-out reference (not deleted) inside the `test.fixme` body, so 73-08 has the exact toast copy/action contract to preserve when wiring the real trigger.

## Deviations from Plan

None - plan executed exactly as written. All three files parse via `playwright test --list`, ESLint/Prettier clean (`pnpm exec eslint tests/web-e2e/tests/writable-shares.spec.ts tests/web-e2e/tests/shared-folder-desync.spec.ts tests/web-e2e/tests/rotation-ux.spec.ts` — 0 errors after `--fix` applied formatting-only changes), and no existing passing case's body was altered.

## Issues Encountered

None. `pnpm --filter @cipherbox/web-e2e exec tsc --noEmit` reported pre-existing errors in `sdk-e2e`/`recovery.spec.ts` from missing built `dist/` for `@cipherbox/*` packages in this fresh worktree checkout (expected per `<worktree_setup>` — those packages are not rebuilt by this test-only plan and no error referenced any of the three files this plan touched).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- 73-07 (SC1 impl) can now remove the `8.4b` fixme guard in `writable-shares.spec.ts` and land the `NavStackEntry.writeKey` fix.
- 73-09 (SC2 impl) can now remove the fixme guard in `shared-folder-desync.spec.ts` and land the `refreshSharedFolder`-on-restore fix.
- 73-08 (SC4 impl) can now remove the fixme guard in `rotation-ux.spec.ts` and wire `useSharedWriteOps.ts` through `runWithFailureUx`, once 73-02/73-05 land the upstream `tombstoned` mapping.
- No blockers for downstream waves.

---
*Phase: 73-shared-write-navigation-correctness-web*
*Completed: 2026-07-10*
