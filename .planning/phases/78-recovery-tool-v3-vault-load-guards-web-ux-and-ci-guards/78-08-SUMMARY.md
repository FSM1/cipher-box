---
phase: 78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards
plan: 08
subsystem: shared-folder-navigation
tags: [shared-folders, race-condition, write-key, generation-token, web-e2e, SC3c, D-08]
requires:
  - SDK sharedFolderTree active-depth state (73-07)
  - useSharedNavigationActions descent/restore flow (73-07/73-09)
provides:
  - Two-layer descent generation guard (web hook + SDK loadSharedFolder)
  - Per-share monotonic seed generation on SharedFolderTree
  - descent-vs-restore.spec.ts permanent regression test
affects:
  - apps/web/src/hooks/useSharedNavigationActions.ts
  - packages/sdk/src/client.ts
  - packages/sdk/src/state/shared-folder-tree.ts
tech-stack:
  added: []
  patterns:
    - monotonic generation token guarding an async apply (mirrors IPNS sequenceNumber clock)
key-files:
  created:
    - tests/web-e2e/tests/descent-vs-restore.spec.ts
    - packages/sdk/src/__tests__/shared-folder-seed-generation.test.ts
  modified:
    - apps/web/src/hooks/useSharedNavigationActions.ts
    - apps/web/src/hooks/shared-folder-projection.ts
    - packages/sdk/src/client.ts
    - packages/sdk/src/state/shared-folder-tree.ts
    - packages/sdk/src/__tests__/shared-folder-tree.test.ts
decisions:
  - Guard at BOTH layers — the SDK holds the authoritative active depth, so its loadSharedFolder is the backstop; the web hook bails before mutating React/nav state
  - navigateToSubfolder restructured so the child seed is applied synchronously after the last guard (no await between guard and apply)
metrics:
  tasks_completed: 2
  files_created: 2
  files_modified: 5
  completed: 2026-07-12
status: complete
---

# Phase 78 Plan 08: Descent-vs-Restore Guard Summary

Threaded a monotonic per-share "active-depth seed generation" through both the web `navigateToSubfolder` hook and the SDK's authoritative `sharedFolderTree`/`loadSharedFolder`, so a subfolder descent that resolves after a racing `navigateUp`/breadcrumb restore is discarded at both layers and can never repoint the active writeKey/depth (SC3c / D-08 item 11).

## What was built

### SDK layer (authoritative backstop)

- `SharedFolderTree` gained a per-share monotonic `seedGenerations` map with `nextSeedGeneration(shareId)` / `currentSeedGeneration(shareId)`. `delete()` bumps the generation (never resets) so an in-flight seed racing an unload is recognised as stale; the counter deliberately survives unload to stay monotonic.
- `CipherBoxClient.loadSharedFolder(shareId, state, seedGeneration?)` now rejects (returns `false`, no mutation) a seed whose captured generation is older than the share's current generation. Unguarded callers (no token — the same-depth adopt/refresh paths) are unaffected. Added `nextSharedFolderSeedGeneration` / `currentSharedFolderSeedGeneration` accessors.

### Web layer

- `navigateToSubfolder` captures the generation before its async descent and re-checks at BOTH await boundaries (`descendSharedChild` and `resolveSharedSubfolderWriteKey`), bailing (and zeroing the minted child readKey/writeKey) before any React/nav-stack mutation if superseded. The child apply + seed is now fully synchronous after the last guard, and the seed forwards the token as the SDK backstop.
- `restoreToBreadcrumbIndex` (navigateUp/breadcrumb), `navigateToShare`, and `navigateToRoot` bump the generation so an in-flight descent is superseded; the restore stamps its own re-seed with the bumped token.
- `shared-folder-projection.ts` forwards `seedGeneration` from `SeedSharedFolderArgs` into `client.loadSharedFolder`.

### Tests

- `tests/web-e2e/tests/descent-vs-restore.spec.ts` (NEW, permanent, never skipped): a deterministic route-interception spec. It holds the descent's `GET /ipns/resolve`, restores to the share root via the breadcrumb while held (the descent's loading state unmounts the file list + parent-dir row, but the breadcrumb nav stays mounted), releases, then asserts the breadcrumb stays at the restored depth, a write lands there, and the file is absent from the descent-target subfolder.
- `packages/sdk/src/__tests__/shared-folder-seed-generation.test.ts` (NEW) and additions to `shared-folder-tree.test.ts`: deterministic unit coverage of the guard — monotonic per-share generation, delete-bumps-generation, and `loadSharedFolder` rejecting a superseded descent token while accepting the restore's current token.

## Verification

- `descent-vs-restore.spec.ts`: 4/4 GREEN against the fix, deterministically (test 3.1 in ~0.4-0.5s, no timing reliance), run twice against the live local stack.
- `packages/sdk` unit tests: 416 passed / 3 skipped (including the 3 new seed-generation tests and the 2 new tree tests).
- `apps/web` vitest: 61 passed / 6 skipped. `apps/web` `tsc -b`: exit 0. web-e2e `tsc`: clean.
- `pnpm lint` on all touched files: clean. sdk dist rebuilt after the `client.ts` edit (cross-package dist staleness).

## Deviations from Plan

### Auto-fixed / adjusted

**1. [Rule 3 - Blocking] e2e in-flight restore trigger changed from navigateUp to the breadcrumb**

- Found during: first e2e run (Task 1/2 verification).
- Issue: the plan's spec sketch used `navigateUp` (the `[..]` parent-dir row). During the held descent the browser is in its loading state, which UNMOUNTS the file list and the parent-dir row (`SharedFileBrowser.tsx` gates the list behind `!isLoading`), so the dblclick auto-waited until the test timed out.
- Fix: click the share-root breadcrumb (`navigateToBreadcrumb(0)` → the same `restoreToBreadcrumbIndex` restore helper). The breadcrumb nav stays mounted during loading, so it is the reliable in-flight restore trigger. This is still a D-08 item-11 "navigateUp/breadcrumb" path.
- Commit: b31c47281.

**2. [Rule 2 - Added coverage] Added SDK unit tests for the guard logic**

- Found during: attempting to demonstrate a clean pre-fix RED for the e2e (see Known Limitation).
- Fix: added deterministic unit tests that gate the guard's core semantics (RED without the guard, GREEN with it), since the e2e's pre-fix behavior is dominated by a pre-existing fail-safe (below) rather than a reproducible misroute.
- Commit: b31c47281.

## Known Limitation — pre-fix e2e RED

The e2e is GREEN against the fix and is a permanent regression lock on the end-to-end invariant (a descent superseded by a restore leaves the write at the viewed depth, with no error and no misroute). A clean pre-fix RED for a data **misroute** could not be isolated through the black-box UI: when a descent is held at its network resolve and a restore fires, the pre-existing restore-time readKey zeroing (`restoreToBreadcrumbIndex` zeroes the current `folderKey`, which is the held descent's parent readKey) makes the held descent **fail-closed** (`unsealChildReadKey` throws on the zeroed key) rather than misroute. The genuine misroute window is the subsequent non-network `resolveSharedSubfolderWriteKey` microtask gap, which macrotask UI clicks cannot interleave into.

The two-layer generation guard is therefore correct defense-in-depth: it makes the SDK's authoritative active depth impossible to repoint by a stale seed on ANY path, and converts the pre-existing fail-closed-with-error into a clean silent discard. The guard's RED/GREEN behavior is locked deterministically by the new SDK unit tests; the e2e locks the integration-level invariant.

## Self-Check: PASSED

- tests/web-e2e/tests/descent-vs-restore.spec.ts — FOUND
- packages/sdk/src/__tests__/shared-folder-seed-generation.test.ts — FOUND
- Commit f041f7e50 (spec), 9eda52273 (fix), b31c47281 (unit tests + e2e harden) — all FOUND in git log
- STATE.md / ROADMAP.md — not modified (worktree mode; orchestrator owns)
