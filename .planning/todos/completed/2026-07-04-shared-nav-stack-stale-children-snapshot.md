---
created: 2026-07-04T00:00:00Z
title: Shared-folder breadcrumb restore shows stale children (snapshot by reference)
area: web
files:
  - apps/web/src/hooks/useSharedNavigationActions.ts:412
source: PR #588 Greptile review (P2 thread — valid, deferred)
---

## Problem

The shared-folder nav stack pushes `children: p.folderChildren` by reference
(useSharedNavigationActions.ts:412-422) so navigateUp/navigateToBreadcrumb can
restore a level without a network round-trip. But `sharedFolder:updated` refresh
events (useSharedNavigation subscription) replace the live children with a fresh
array, while the stack still holds the OLD reference. Navigating up/to a
breadcrumb therefore restores a stale snapshot — the user can see deleted
children or miss newly added ones until they reopen the folder. Clicking a stale
child walks the read chain to an outdated IPNS entry (resolves stale/fails; the
chain still validates, so not a security breach — a UX-staleness P2).

Pre-existing snapshot design (68.1-30), not introduced by the 68.1 ship pass.

## Solution

On breadcrumb/up navigation for shared folders, re-resolve the target level's
children from the network (like the owned-tree resyncFolder path) instead of
restoring the cached snapshot — or invalidate stack snapshots when a
`sharedFolder:updated` event fires for that depth. Gate with a shared-folder
web-e2e that mutates a folder from a second client while navigated deeper, then
navigates up. Relates to [[consolidate-web-shared-navigation-dup]] and
[[web-sdk-folder-state-desync]].
