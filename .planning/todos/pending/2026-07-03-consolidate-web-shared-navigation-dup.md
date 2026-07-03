---
created: 2026-07-03T00:00:00Z
title: Consolidate shared-navigation and ShareDialog duplication in web
area: web
files:
  - apps/web/src/hooks/useSharedNavigationActions.ts:500
  - apps/web/src/hooks/useSharedNavigationActions.ts:765
  - apps/web/src/components/file-browser/ShareDialog.tsx:44
source: ship-phase 68.1 simplify review
---

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
