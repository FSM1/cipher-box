---
phase: 48-sdk-self-bootstrap-regression-fix-and-shared-folder-metadata
plan: "04"
subsystem: web
tags: [web, shared-folder, projection, events, REQ-3]
dependency_graph:
  requires: ["48-03"]
  provides: ["REQ-3"]
  affects:
    [
      "apps/web/src/hooks/shared-folder-projection.ts",
      "apps/web/src/hooks/useSharedWriteOps.ts",
      "apps/web/src/hooks/useSharedNavigation.ts",
      "apps/web/src/hooks/useSharedNavigationActions.ts",
    ]
tech_stack:
  added: []
  patterns:
    - "Shared write hook is projection-only: handlers call getSdkClient().<sharedMethod>(shareId, args) and read NOTHING back"
    - "folderChildrenRef/sequenceNumberRef written ONLY by a sharedFolder:updated subscription, filtered on the active shareId (read via ref at event time)"
    - "SDK re-seeded (loadSharedFolder) at every navigation depth change — share-enter, subfolder-enter, up, breadcrumb — because sharedFolderTree is keyed by shareId but the web navigates distinct ipnsName/folderKey/IPNS-key per depth"
key_files:
  created:
    - apps/web/src/hooks/shared-folder-projection.ts
    - apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts
  modified:
    - apps/web/src/hooks/useSharedWriteOps.ts
    - apps/web/src/hooks/useSharedNavigation.ts
    - apps/web/src/hooks/useSharedNavigationActions.ts
decisions:
  - "Extracted seedSharedFolder + subscribeSharedFolderProjection into a framework-agnostic shared-folder-projection.ts so the projection contract is unit-testable in the web vitest node env (no React render harness — mirrors the owned-path folder.store.test.ts strategy)."
  - "The SDK sharedFolderTree is keyed by shareId, but the web navigates subfolders within one share (each with a distinct ipnsName/folderKey/IPNS private key/sequence). So loadSharedFolder is re-invoked at every navigation depth change (share-enter, subfolder-enter, navigateUp, navigateToBreadcrumb), overwriting the prior depth's state under the same shareId. Only write shares (IPNS key present) are seeded."
  - "withRevocationGuard (403 detection) retained on the web side — it is orthogonal to CAS and the revocation UX (zero key, flip read-only) is web state. withConflictRetry/resyncSharedFolder/buildSharedWriteContext removed (the SDK's publishWithCas subsumes retry)."
metrics:
  duration: "~12 minutes"
  completed: "2026-06-16"
  tasks_completed: 3
  tasks_total: 4
  files_created: 2
  files_modified: 3
---

# Phase 48 Plan 04: Shared-folder write projection (web) Summary

The web shared-write hook now routes all five mutations through the SDK client's
`(shareId, args)` shared methods and reads nothing back; `useSharedNavigation`'s
`folderChildrenRef`/`sequenceNumberRef` become event-fed projections driven
solely by the `sharedFolder:updated` subscription — completing REQ-3 so the SDK
is the single source of truth for shared-folder state.

## What Was Built (REQ-3, web side)

Mirrors the Phase-47 owned-path consolidation (useFileOperations/useFileVersions)
applied to the shared path.

### New helper module — `shared-folder-projection.ts`

Framework-agnostic (node-testable) helpers:

- `seedSharedFolder(client, args)` → `client.loadSharedFolder(shareId, state)`:
  seeds/re-seeds the SDK's `sharedFolderTree` for the active depth.
- `subscribeSharedFolderProjection(client, getActiveShareId, apply)`: subscribes
  to `sharedFolder:updated`, ignores non-matching event types, and filters on
  `event.shareId === getActiveShareId()` (read at event time via ref) before
  applying `children`/`sequenceNumber` — the only post-mutation writer of the
  projection. Returns the unsubscribe.
- `parsePublicKey(hex)`: moved here from the write hook (used by the seed sites).

### `useSharedWriteOps.ts` — projection-only

- All five handlers (`uploadFile`/`createFolder`/`renameItem`/`updateSharedFile`/
  `deleteItem`) call `getSdkClient().<sharedMethod>(currentShareId, args)` and
  read NOTHING back — the four write-back lines per handler are gone.
- `withConflictRetry`/`resyncSharedFolder`/`buildSharedWriteContext`/`freshCtx`
  ceremony removed; the SDK's `publishWithCas` owns retry.
- `withRevocationGuard` (403 → read-only) retained.
- Params slimmed: the hook no longer receives/owns the refs or setters.

### `useSharedNavigation.ts` — subscription + seed wiring

- Added a stable `currentShareIdRef` mirror (read by the projection at event time).
- Added a `sharedFolder:updated` subscription effect — the ONLY writer of
  `folderChildrenRef`/`sequenceNumberRef` + setters post-mutation.
- Added `seedActiveSharedFolder` (wraps `seedSharedFolder` with the live
  `addShareKeysFn`), passed into the nav actions.

### `useSharedNavigationActions.ts` — seed at every depth change

- `navigateToShare` (folder write case), `navigateToSubfolder` (after IPNS key
  restore), and `navigateUp`/`navigateToBreadcrumb` (via a new
  `reseedRestoredDepth` after `restoreIpnsKeyForDepth`) all re-seed the SDK for
  the new depth. Read-only shares are not seeded (cannot write).

## Task Commits

| Task | Name | Commit |
| ---- | ---- | ------ |
| 1+2+3 | Seed + subscription + write rerouting + projection unit test | 0949e1f43 |

Tasks 1-3 are tightly coupled (the projection module, both hooks, and the test
move together as one atomic change) and were committed together. Task 4 is a
UAT checkpoint (see below).

## Verification

- SDK dist rebuilt first (cross-package staleness): `pnpm --filter @cipherbox/sdk-core build && pnpm --filter @cipherbox/sdk build` — both succeeded.
- `tsc -p tsconfig.json --noEmit` (apps/web): exit 0. (`@cipherbox/web` has no `typecheck` script; the build runs `tsc -b` — used the direct project invocation, equivalent.)
- `pnpm --filter @cipherbox/web test useSharedWriteOps`: 6 passed.
- `eslint` on all five touched files: exit 0 (one prettier wrap + one unused import auto-fixed).

Acceptance greps:

- `grep "folderChildrenRef.current =" useSharedWriteOps.ts` → NONE (write-back removed).
- `grep "sequenceNumberRef.current =" useSharedWriteOps.ts` → NONE.
- `grep "withConflictRetry" useSharedWriteOps.ts` → NONE.
- `grep "sharedFolder:updated\|subscribeSharedFolderProjection" useSharedNavigation.ts` → present (subscription wired).

## Checkpoint (Task 4 — Shared-folder write UAT)

Task 4 is a `checkpoint:human-verify` (shared-write UAT as a write-share
recipient: upload / mkdir / rename / edit / delete reflect immediately and
persist, no stale-sequence 409 loop). Per the execution directive this was NOT
blocked — the code is committed and the UAT is delegated to the end-of-phase
web-e2e (desktop cross-client-sync / shared-folder specs).

## Deviations from Plan

### Structure: extracted a projection helper module (not in plan's file list)

The plan listed only `useSharedWriteOps.ts` + `useSharedNavigation.ts` +
the test. Because the web vitest env is `node` (no React render harness), the
projection/seed logic was extracted into a new framework-agnostic
`apps/web/src/hooks/shared-folder-projection.ts` so the REQ-3 contract is
unit-testable directly — the same strategy the owned path used
(`folder.store.test.ts` tests the projection handler, not the hook). This keeps
the test honest without adding `@testing-library/react`. Tracked as a structural
deviation; no behavior change beyond the plan's intent.

### Seed site is the nav actions, re-seeded per depth

The plan's Task 1 described seeding "when a share becomes active." In practice
the active folder context changes on subfolder entry and on up/breadcrumb too
(distinct ipnsName/folderKey/IPNS key per depth under one shareId), so
`loadSharedFolder` is re-invoked at all four navigation points — not just
share-enter. This is required for correctness (otherwise a subfolder write would
publish against the parent's stale context).

No Rule 1-3 auto-fixes were required; the analogs matched the codebase.

## Known Stubs

None.

## Threat Flags

None — no new network endpoints, auth paths, or trust-boundary surface. The
`addShareKeysFn` passed into the SDK is the same callback the hook used before
(T-48-11 accept). The projection's shareId filter implements the T-48-09/T-48-10
mitigations (asserted by the per-share isolation + mismatched-shareId tests).

## Risk Notes

- **Shared-folder state desync risk (the class this phase eliminates):** the
  refs are now written by exactly one path (the subscription). The residual risk
  is the SEED staying in sync with what is displayed — if a navigation path set
  the displayed children but failed to re-seed the SDK, a subsequent write would
  publish against a stale depth context. All four navigation entry points seed;
  the 30s poller still calls `refreshFolderContents` (which updates the display
  refs but does NOT re-seed the SDK) — acceptable because the SDK re-reads its
  own state and `publishWithCas` self-corrects sequence, but a poll-then-write
  without intervening navigation relies on CAS rather than a fresh seed. The
  end-of-phase web-e2e shared-folder spec is the integration gate for this.

## Self-Check: PASSED

- `apps/web/src/hooks/shared-folder-projection.ts` — FOUND
- `apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts` — FOUND
- `apps/web/src/hooks/useSharedWriteOps.ts` — FOUND (modified)
- `apps/web/src/hooks/useSharedNavigation.ts` — FOUND (modified)
- `apps/web/src/hooks/useSharedNavigationActions.ts` — FOUND (modified)
- Commit `0949e1f43` — present in git history.
