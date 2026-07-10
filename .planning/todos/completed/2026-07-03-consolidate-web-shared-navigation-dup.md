---
created: 2026-07-03T00:00:00Z
title: Consolidate shared-navigation and ShareDialog duplication in web
area: web
files:
  - apps/web/src/hooks/useSharedNavigationActions.ts:500
  - apps/web/src/hooks/useSharedNavigationActions.ts:765
  - apps/web/src/components/file-browser/ShareDialog.tsx:44
source: ship-phase 68.1 simplify review
status: completed
resolved: 2026-07-10
resolution: partial — genuine duplication removed; the 9-site resolveKinds unification evaluated and deliberately declined (see Resolution)
---

## Resolution (2026-07-10)

Closed. The genuine duplication this todo targeted has been removed; the one
remaining item (the "resolveKinds-then-project util across ~9 sites") was
investigated end-to-end and **deliberately declined** — it is a family of
intentionally-distinct variants, not a mechanical duplicate.

Done (Phase 73 + 2026-07-10 follow-up):

- SC6 restore consolidation — `navigateUp`/`navigateToBreadcrumb` folded into one
  `restoreToBreadcrumbIndex(crumbIndex)` helper (Phase 73, 73-06).
- Dead `resolveFolderIpnsPrivateKey` + orphaned JSDoc removed (Phase 73, 73-06).
- `readSharedContent` extracted — `downloadSharedFile` / `loadSharedFileContent`
  now share one read-core helper preserving exact error strings and control flow
  (commit `ef3c5e77b`).
- `parseRootGeneration` exported from `share.service.ts` and imported by
  `ShareDialog.tsx` (commit `334d4c492`).
- `resolveFileIpnsKey` mirror — MOOT (its `resolveFolderIpnsPrivateKey` analog was
  deleted in Phase 73).

Declined (with rationale, see back-out analysis below): the resolveKinds-then-project
consolidation. It has **zero user impact** (behavior-neutral by definition), the sites
are load-bearing-distinct rather than duplicated (so a helper gives no "fix-once"
benefit and could mask intentional guard differences), and unifying would require
changing observable guard/timing semantics in security-critical navigation with no
CI-gated e2e. Net value low, risk moderate-to-high. **Do not reopen as a mechanical
refactor** — if ever revisited, scope it as a from-scratch redesign with explicit
sign-off on which guard semantics may change.

Verification of the landed changes: `pnpm typecheck` exit 0; eslint clean;
web-e2e `writable-shares.spec.ts` + `shared-folder-desync.spec.ts` 35/35 against the
live stack (owned-folder nav byte-for-byte unchanged).

## Partially resolved (Phase 73, 2026-07-10)

Phase 73 (SC6/SC7, plan 73-06) resolved two of the sub-items below:

- The `navigateUp` vs `navigateToBreadcrumb` ~55-line near-verbatim restore+re-seed
  block was consolidated into a single `restoreToBreadcrumbIndex(crumbIndex)` helper
  (`navigateUp` now delegates with `stack.length - 1`).
- The dead `resolveFolderIpnsPrivateKey` path and its orphaned JSDoc block were
  deleted (tracked separately by the now-completed
  `2026-07-04-remove-dead-getsharekeys-folder-ipns-path` todo).

## Follow-up resolved (2026-07-10)

Three of the four remaining sub-items are now closed:

- `resolveFileIpnsKey` (useSharedWriteOps.ts) mirror: MOOT. `resolveFolderIpnsPrivateKey`
  no longer exists anywhere in `apps/web` (confirmed by grep) -- `resolveFileIpnsKey` is
  a lone function with nothing left to dedup against.
- ShareDialog `parseRootGeneration`/sent-shares dedup: `parseRootGeneration` (byte-identical
  in both places) is now exported from `share.service.ts` and imported by `ShareDialog.tsx`
  instead of a local copy. `toSentShare`/`fetchAllSentShares` were also exported, but
  ShareDialog's inline pagination+DTO-mapping was intentionally NOT swapped to call them:
  it filters to the single shared item (the service versions fetch/return the full
  unfiltered list), seeds `itemName` from the local `item.name` (the service versions hardcode
  `''`), and uses a stricter truthy `permission` check (the service's `toSentShare` uses
  `!= null`, which would misclassify an empty-string `encryptedWriteKey` as write) -- swapping
  would have been a silent behavior change, not a pure refactor.
- `readSharedContent` dedup (`loadSharedFileContent` ≡ `downloadSharedFile`): DONE. Both now
  call a shared `readSharedContent(share, path, vaultKeypair)` helper in
  `useSharedNavigationActions.ts` that builds the `client.downloadSharedFile` request and maps
  `revoked`/`behind-retry` to marker errors (`SharedFileRevokedError`/`SharedFileBehindRetryError`)
  carrying the exact pre-existing message strings. `loadSharedFileContent` lets them propagate
  (unchanged throw-based behavior); `downloadSharedFile` catches them by `instanceof` and restores
  its exact `setError`-then-return control flow, so its generic catch-all
  (`logger.error` + "Failed to download file") still only fires for genuinely unexpected errors.

**Declined — NOT safely unifiable (back-out analysis, 2026-07-10):** the single resolveKinds-then-project
util across the ~9 sites. A full investigation (reading every cited site plus adjacent ones
found via grep) found the "pattern" is a family, not a duplicate -- every site differs in a way
that's load-bearing, not incidental:

- Owned plane has (at least) 5 independent variants of "listFolder + ensureFolderLoaded ->
  updateFolderChildren/RawChildren/Sequence": `useFolderNavigation.ts`'s `refreshFolderListing`
  (parallel `Promise.all`, post-await presence-only guard), `folder-helpers.ts`'s `resyncFolder`
  (pre-check before calling the SDK at all, sequential await), `useFileBrowserActions.ts`'s
  `handleSync` (pre-check, sequential, wrapped in `runWithFailureUx` for D-05 toast surfacing,
  no post-await re-check, plus `triggerSearchIndexRebuild()`), `useSyncPolling.ts`'s
  `invalidateOpenFolder` (pre-check, parallel, post-await guard checks BOTH folder-presence AND
  "is this still the open folder"), and `useFolderNavigation.ts`'s `navigateTo` cold-load path
  (an 8x-retry loop with a `latestNavTarget` ref-equality guard checked at 3 points, placeholder
  insertion, and catch-based rollback -- not a simple resolve+project at all). `folder.store.ts`'s
  `subscribeToSdk` event handler is a 6th, event-driven variant with its own
  empty-over-populated + strict `>` (not `>=`) sequence guard, and deliberately skips
  `updateFolderRawChildren`.
- Shared plane has (at least) 4 independent variants: `navigateToShare` (`resolveShareRoot`,
  resets the nav stack, root-writeKey derivation, its own revoked/behind-retry message text),
  `navigateToSubfolder` (`descendSharedChild`, pushes a nav-stack entry capturing the
  pre-descent `publishedNode`, different writeKey derivation call/args, different message text),
  `restoreToBreadcrumbIndex` (no new resolve at all -- restores from the in-memory nav-stack
  snapshot, then an *additive* background `refreshSharedFolder` re-resolve with no local guard,
  relying entirely on the SDK's own internal monotonicity check), and `useSharedNavigation.ts`'s
  resolved-display effect (`listSharedFolder` for the current depth, guarded by a React-effect
  `cancelled` closure flag, not a ref/counter). `shared-folder-projection.ts`'s
  `subscribeSharedFolderProjection` is already a clean, reusable, event-driven consolidation
  point for the shared plane's push-based update -- it needs no further work.

Every difference above is explained by an inline comment tied to a specific correctness
requirement (73-07 SC1 write-key lifecycle/zeroization, 73-09 SC2 staleness, D-03 deterministic
freshness, D-05 error-surfacing, D-09 buffer ownership, SC#3 "never independently resolve").
Unifying any two of these would require either changing observable guard/timing behavior (parallel
vs sequential SDK calls, pre-check vs post-check, `>` vs `>=`) or parameterizing over so many axes
(resolve strategy, guard predicate, projection field set, error-handling wrapper, side effects)
that the result would be a thin dispatch shim reproducing each site's logic anyway -- no real
DRY benefit, and a large new surface in security/correctness-critical navigation code. Per this
todo's own back-out clause, this sub-item is intentionally left as-is: behavior neutrality and
owned-folder-navigation safety outweigh closing it. If revisited, scope it as a from-scratch
design task (not a mechanical extraction) and get an explicit sign-off on which guard semantics
are allowed to change.

## Problem

- `loadSharedFileContent` (useSharedNavigationActions.ts:765) duplicates
  `downloadSharedFile`'s (:678-763) read core verbatim (~35 lines, self-documented
  mirror) — one `readSharedContent(share, path)` helper replaces both.
- `navigateUp` (:500) vs `navigateToBreadcrumb` (:591-676): ~55-line near-verbatim
  restore+re-seed block; navigateUp ≡ restore-to-index(len−1).
- The resolveKinds-before-project pattern is wired 4 different ways across 9 sites
  (useFolderNavigation:273, folder-helpers:35, useFileBrowserActions:145,
  useSharedNavigationActions:272/390/520/608, folder.store:249, useSharedNavigation:332)
  — consolidate into one helper with the stale-sequence guard.
- ShareDialog.tsx:44/:118 — `parseRootGeneration` verbatim copy of
  share.service.ts:86 (unexported there); inline sent-shares pagination + DTO
  mapping duplicate `fetchAllSentShares`/`toSentShare`.
- Orphaned JSDoc block at useSharedNavigationActions.ts:138 (documents
  `resolveFolderIpnsPrivateKey`, stranded above a different function); and
  useSharedWriteOps.ts:50 `resolveFileIpnsKey` mirrors
  `resolveFolderIpnsPrivateKey` (:175) modulo one keyType literal.

## Solution

Extract shared helpers (readSharedContent, restoreToBreadcrumbIndex, a single
resolveKinds-then-project util; export parseRootGeneration/toSentShare from
share.service). UI-behavior-neutral refactor — gate with the shared-folder and
writable-shares web-e2e spec files, not unit tests (web UI has none by policy).
